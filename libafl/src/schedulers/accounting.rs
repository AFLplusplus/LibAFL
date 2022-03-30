//! Coverage accounting corpus scheduler, more details at <https://www.ndss-symposium.org/wp-content/uploads/2020/02/24422-paper.pdf>

use crate::{
    bolts::{rands::Rand, AsMutSlice, AsSlice, HasLen, HasRefCnt},
    corpus::{Corpus, Testcase},
    feedbacks::MapIndexesMetadata,
    inputs::Input,
    schedulers::{
        minimizer::{IsFavoredMetadata, MinimizerScheduler, DEFAULT_SKIP_NON_FAVORED_PROB},
        LenTimeMulTestcaseScore, Scheduler,
    },
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

use alloc::vec::Vec;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

/// A testcase metadata holding a list of indexes of a map
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountingIndexesMetadata {
    /// The list of indexes.
    pub list: Vec<usize>,
    /// A refcount used to know when remove this meta
    pub tcref: isize,
}

crate::impl_serdeany!(AccountingIndexesMetadata);

impl AsSlice<usize> for AccountingIndexesMetadata {
    /// Convert to a slice
    fn as_slice(&self) -> &[usize] {
        self.list.as_slice()
    }
}
impl AsMutSlice<usize> for AccountingIndexesMetadata {
    /// Convert to a slice
    fn as_mut_slice(&mut self) -> &mut [usize] {
        self.list.as_mut_slice()
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
pub struct TopAccountingMetadata {
    /// map index -> corpus index
    pub map: HashMap<usize, usize>,
    /// If changed sicne the previous add to the corpus
    pub changed: bool,
    /// The max accounting seen so far
    pub max_accounting: Vec<u32>,
}

crate::impl_serdeany!(TopAccountingMetadata);

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
pub struct CoverageAccountingScheduler<'a, CS, I, S>
where
    CS: Scheduler<I, S>,
    I: Input + HasLen,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    accounting_map: &'a [u32],
    skip_non_favored_prob: u64,
    inner: MinimizerScheduler<CS, LenTimeMulTestcaseScore<I, S>, I, MapIndexesMetadata, S>,
}

impl<'a, CS, I, S> Scheduler<I, S> for CoverageAccountingScheduler<'a, CS, I, S>
where
    CS: Scheduler<I, S>,
    I: Input + HasLen,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        self.update_accounting_score(state, idx)?;
        self.inner.on_add(state, idx)
    }

    fn on_replace(&self, state: &mut S, idx: usize, testcase: &Testcase<I>) -> Result<(), Error> {
        self.inner.on_replace(state, idx, testcase)
    }

    fn on_remove(
        &self,
        state: &mut S,
        idx: usize,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        self.inner.on_remove(state, idx, testcase)
    }

    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state
            .metadata()
            .get::<TopAccountingMetadata>()
            .map_or(false, |x| x.changed)
        {
            self.accounting_cull(state)?;
        } else {
            self.inner.cull(state)?;
        }
        let mut idx = self.inner.base().next(state)?;
        while {
            let has = !state
                .corpus()
                .get(idx)?
                .borrow()
                .has_metadata::<IsFavoredMetadata>();
            has
        } && state.rand_mut().below(100) < self.skip_non_favored_prob
        {
            idx = self.inner.base().next(state)?;
        }
        Ok(idx)
    }
}

impl<'a, CS, I, S> CoverageAccountingScheduler<'a, CS, I, S>
where
    CS: Scheduler<I, S>,
    I: Input + HasLen,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    /// Update the `Corpus` score
    #[allow(clippy::unused_self)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn update_accounting_score(&self, state: &mut S, idx: usize) -> Result<(), Error> {
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
                    let top_acc = state.metadata().get::<TopAccountingMetadata>().unwrap();

                    if let Some(old_idx) = top_acc.map.get(&idx) {
                        if top_acc.max_accounting[idx] > self.accounting_map[idx] {
                            continue;
                        }

                        if top_acc.max_accounting[idx] >= self.accounting_map[idx] {
                            equal_score = true;
                        }

                        let mut old = state.corpus().get(*old_idx)?.borrow_mut();
                        let must_remove = {
                            let old_meta = old.metadata_mut().get_mut::<AccountingIndexesMetadata>().ok_or_else(|| {
                                Error::KeyNotFound(format!(
                                    "AccountingIndexesMetadata, needed by CoverageAccountingScheduler, not found in testcase #{}",
                                    old_idx
                                ))
                            })?;
                            *old_meta.refcnt_mut() -= 1;
                            old_meta.refcnt() <= 0
                        };

                        if must_remove {
                            drop(old.metadata_mut().remove::<AccountingIndexesMetadata>());
                        }
                    }
                }

                let top_acc = state
                    .metadata_mut()
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

        state.corpus().get(idx)?.borrow_mut().metadata_mut().insert(
            AccountingIndexesMetadata::with_tcref(indexes, new_favoreds.len() as isize),
        );

        let top_acc = state
            .metadata_mut()
            .get_mut::<TopAccountingMetadata>()
            .unwrap();
        top_acc.changed = true;

        for elem in new_favoreds {
            top_acc.map.insert(elem, idx);
        }

        Ok(())
    }

    /// Cull the `Corpus`
    #[allow(clippy::unused_self)]
    pub fn accounting_cull(&self, state: &mut S) -> Result<(), Error> {
        let top_rated = match state.metadata().get::<TopAccountingMetadata>() {
            None => return Ok(()),
            Some(val) => val,
        };

        for (_key, idx) in &top_rated.map {
            let mut entry = state.corpus().get(*idx)?.borrow_mut();
            if entry.fuzzed() {
                continue;
            }

            entry.add_metadata(IsFavoredMetadata {});
        }

        Ok(())
    }

    /// Creates a new [`CoverageAccountingScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a default probability to skip non-faved [`Testcase`]s of [`DEFAULT_SKIP_NON_FAVORED_PROB`].
    pub fn new(state: &mut S, base: CS, accounting_map: &'a [u32]) -> Self {
        match state.metadata().get::<TopAccountingMetadata>() {
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
            inner: MinimizerScheduler::new(base),
            skip_non_favored_prob: DEFAULT_SKIP_NON_FAVORED_PROB,
        }
    }

    /// Creates a new [`CoverageAccountingScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a non-default probability to skip non-faved [`Testcase`]s using (`skip_non_favored_prob`).
    pub fn with_skip_prob(
        state: &mut S,
        base: CS,
        skip_non_favored_prob: u64,
        accounting_map: &'a [u32],
    ) -> Self {
        match state.metadata().get::<TopAccountingMetadata>() {
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
            inner: MinimizerScheduler::with_skip_prob(base, skip_non_favored_prob),
            skip_non_favored_prob,
        }
    }
}
