//! Coverage accounting corpus scheduler, more details at <https://www.ndss-symposium.org/wp-content/uploads/2020/02/24422-paper.pdf>

use alloc::vec::Vec;
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use hashbrown::HashMap;
use libafl_bolts::{rands::Rand, HasLen, HasRefCnt};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId},
    feedbacks::MapIndexesMetadata,
    inputs::UsesInput,
    observers::{CanTrack, ObserversTuple},
    schedulers::{
        minimizer::{IsFavoredMetadata, MinimizerScheduler, DEFAULT_SKIP_NON_FAVORED_PROB},
        LenTimeMulTestcaseScore, Scheduler,
    },
    state::{HasCorpus, HasRand, UsesState},
    Error, HasMetadata,
};

/// A testcase metadata holding a list of indexes of a map
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct AccountingIndexesMetadata {
    /// The list of indexes.
    pub list: Vec<usize>,
    /// A refcount used to know when remove this meta
    pub tcref: isize,
}

libafl_bolts::impl_serdeany!(AccountingIndexesMetadata);

impl Deref for AccountingIndexesMetadata {
    type Target = [usize];
    fn deref(&self) -> &[usize] {
        &self.list
    }
}
impl DerefMut for AccountingIndexesMetadata {
    fn deref_mut(&mut self) -> &mut [usize] {
        &mut self.list
    }
}

impl HasRefCnt for AccountingIndexesMetadata {
    fn refcnt(&self) -> isize {
        self.tcref
    }

    fn refcnt_mut(&mut self) -> &mut isize {
        &mut self.tcref
    }
}

impl AccountingIndexesMetadata {
    /// Creates a new [`struct@AccountingIndexesMetadata`].
    #[must_use]
    pub fn new(list: Vec<usize>) -> Self {
        Self { list, tcref: 0 }
    }

    /// Creates a new [`struct@AccountingIndexesMetadata`] specifying the refcount.
    #[must_use]
    pub fn with_tcref(list: Vec<usize>, tcref: isize) -> Self {
        Self { list, tcref }
    }
}

/// A state metadata holding a map of favoreds testcases for each map entry
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct TopAccountingMetadata {
    /// map index -> corpus index
    pub map: HashMap<usize, CorpusId>,
    /// If changed sicne the previous add to the corpus
    pub changed: bool,
    /// The max accounting seen so far
    pub max_accounting: Vec<u32>,
}

libafl_bolts::impl_serdeany!(TopAccountingMetadata);

impl TopAccountingMetadata {
    /// Creates a new [`struct@TopAccountingMetadata`]
    #[must_use]
    pub fn new(acc_len: usize) -> Self {
        Self {
            map: HashMap::default(),
            changed: false,
            max_accounting: vec![0; acc_len],
        }
    }
}

/// A minimizer scheduler using coverage accounting
#[derive(Debug)]
pub struct CoverageAccountingScheduler<'a, CS, O>
where
    CS: UsesState,
    CS::State: Debug,
{
    accounting_map: &'a [u32],
    skip_non_favored_prob: f64,
    inner: MinimizerScheduler<
        CS,
        LenTimeMulTestcaseScore<<CS as UsesState>::State>,
        MapIndexesMetadata,
        O,
    >,
}

impl<'a, CS, O> UsesState for CoverageAccountingScheduler<'a, CS, O>
where
    CS: UsesState,
    CS::State: Debug,
{
    type State = CS::State;
}

impl<'a, CS, O> Scheduler for CoverageAccountingScheduler<'a, CS, O>
where
    CS: Scheduler,
    Self::State: HasCorpus + HasMetadata + HasRand,
    CS::State: Debug,
    <Self::State as UsesInput>::Input: HasLen,
    O: CanTrack,
{
    fn on_add(&mut self, state: &mut Self::State, id: CorpusId) -> Result<(), Error> {
        self.update_accounting_score(state, id)?;
        self.inner.on_add(state, id)
    }

    fn on_evaluation<OT>(
        &mut self,
        state: &mut Self::State,
        input: &<Self::State as UsesInput>::Input,
        observers: &OT,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<Self::State>,
    {
        self.inner.on_evaluation(state, input, observers)
    }

    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if state
            .metadata_map()
            .get::<TopAccountingMetadata>()
            .map_or(false, |x| x.changed)
        {
            self.accounting_cull(state)?;
        } else {
            self.inner.cull(state)?;
        }
        let mut id = self.inner.base_mut().next(state)?;
        while {
            let has = !state
                .corpus()
                .get(id)?
                .borrow()
                .has_metadata::<IsFavoredMetadata>();
            has
        } && state.rand_mut().coinflip(self.skip_non_favored_prob)
        {
            id = self.inner.base_mut().next(state)?;
        }

        // Don't add corpus.curret(). The inner scheduler will take care of it

        Ok(id)
    }

    /// Set current fuzzed corpus id and `scheduled_count`
    fn set_current_scheduled(
        &mut self,
        _state: &mut Self::State,
        _next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        // We do nothing here, the inner scheduler will take care of it
        Ok(())
    }
}

impl<'a, CS, O> CoverageAccountingScheduler<'a, CS, O>
where
    CS: Scheduler,
    CS::State: HasCorpus + HasMetadata + HasRand + Debug,
    <CS::State as UsesInput>::Input: HasLen,
    O: CanTrack,
{
    /// Update the `Corpus` score
    #[allow(clippy::unused_self)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn update_accounting_score(
        &self,
        state: &mut CS::State,
        id: CorpusId,
    ) -> Result<(), Error> {
        let mut indexes = vec![];
        let mut new_favoreds = vec![];
        {
            for idx in 0..self.accounting_map.len() {
                if self.accounting_map[idx] == 0 {
                    continue;
                }
                indexes.push(idx);

                let mut equal_score = false;
                {
                    let top_acc = state.metadata_map().get::<TopAccountingMetadata>().unwrap();

                    if let Some(old_id) = top_acc.map.get(&idx) {
                        if top_acc.max_accounting[idx] > self.accounting_map[idx] {
                            continue;
                        }

                        if top_acc.max_accounting[idx] == self.accounting_map[idx] {
                            equal_score = true;
                        }

                        let mut old = state.corpus().get_from_all(*old_id)?.borrow_mut();
                        let must_remove = {
                            let old_meta = old.metadata_map_mut().get_mut::<AccountingIndexesMetadata>().ok_or_else(|| {
                                Error::key_not_found(format!(
                                    "AccountingIndexesMetadata, needed by CoverageAccountingScheduler, not found in testcase #{old_id}"
                                ))
                            })?;
                            *old_meta.refcnt_mut() -= 1;
                            old_meta.refcnt() <= 0
                        };

                        if must_remove {
                            drop(old.metadata_map_mut().remove::<AccountingIndexesMetadata>());
                        }
                    }
                }

                let top_acc = state
                    .metadata_map_mut()
                    .get_mut::<TopAccountingMetadata>()
                    .unwrap();

                // if its accounting is equal to others', it's not favored
                if equal_score {
                    top_acc.map.remove(&idx);
                } else if top_acc.max_accounting[idx] < self.accounting_map[idx] {
                    new_favoreds.push(idx);

                    top_acc.max_accounting[idx] = self.accounting_map[idx];
                }
            }
        }

        if new_favoreds.is_empty() {
            return Ok(());
        }

        state
            .corpus()
            .get(id)?
            .borrow_mut()
            .metadata_map_mut()
            .insert(AccountingIndexesMetadata::with_tcref(
                indexes,
                new_favoreds.len() as isize,
            ));

        let top_acc = state
            .metadata_map_mut()
            .get_mut::<TopAccountingMetadata>()
            .unwrap();
        top_acc.changed = true;

        for elem in new_favoreds {
            top_acc.map.insert(elem, id);
        }

        Ok(())
    }

    /// Cull the `Corpus`
    #[allow(clippy::unused_self)]
    pub fn accounting_cull(&self, state: &CS::State) -> Result<(), Error> {
        let Some(top_rated) = state.metadata_map().get::<TopAccountingMetadata>() else {
            return Ok(());
        };

        for (_key, id) in &top_rated.map {
            let mut entry = state.corpus().get(*id)?.borrow_mut();
            if entry.scheduled_count() > 0 {
                continue;
            }

            entry.add_metadata(IsFavoredMetadata {});
        }

        Ok(())
    }

    /// Creates a new [`CoverageAccountingScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a default probability to skip non-faved Testcases of [`DEFAULT_SKIP_NON_FAVORED_PROB`].
    ///
    /// Provide the observer responsible for determining new indexes.
    pub fn new(observer: &O, state: &mut CS::State, base: CS, accounting_map: &'a [u32]) -> Self {
        match state.metadata_map().get::<TopAccountingMetadata>() {
            Some(meta) => {
                if meta.max_accounting.len() != accounting_map.len() {
                    state.add_metadata(TopAccountingMetadata::new(accounting_map.len()));
                }
            }
            None => {
                state.add_metadata(TopAccountingMetadata::new(accounting_map.len()));
            }
        }
        Self {
            accounting_map,
            inner: MinimizerScheduler::new(observer, base),
            skip_non_favored_prob: DEFAULT_SKIP_NON_FAVORED_PROB,
        }
    }

    /// Creates a new [`CoverageAccountingScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a non-default probability to skip non-faved Testcases using (`skip_non_favored_prob`).
    ///
    /// Provide the observer responsible for determining new indexes.
    pub fn with_skip_prob(
        observer: &O,
        state: &mut CS::State,
        base: CS,
        skip_non_favored_prob: f64,
        accounting_map: &'a [u32],
    ) -> Self {
        match state.metadata_map().get::<TopAccountingMetadata>() {
            Some(meta) => {
                if meta.max_accounting.len() != accounting_map.len() {
                    state.add_metadata(TopAccountingMetadata::new(accounting_map.len()));
                }
            }
            None => {
                state.add_metadata(TopAccountingMetadata::new(accounting_map.len()));
            }
        }
        Self {
            accounting_map,
            inner: MinimizerScheduler::with_skip_prob(observer, base, skip_non_favored_prob),
            skip_non_favored_prob,
        }
    }
}
