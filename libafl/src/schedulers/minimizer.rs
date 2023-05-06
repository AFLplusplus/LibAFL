//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer
//! with testcases only from a subset of the total corpus.

use alloc::vec::Vec;
use core::{any::type_name, cmp::Ordering, marker::PhantomData};

use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{rands::Rand, serdeany::SerdeAny, AsSlice, HasRefCnt},
    corpus::{Corpus, CorpusId, Testcase},
    feedbacks::MapIndexesMetadata,
    inputs::UsesInput,
    observers::ObserversTuple,
    schedulers::{LenTimeMulTestcaseScore, RemovableScheduler, Scheduler, TestcaseScore},
    state::{HasCorpus, HasMetadata, HasRand, UsesState},
    Error,
};

/// Default probability to skip the non-favored values
pub const DEFAULT_SKIP_NON_FAVORED_PROB: u64 = 95;

/// A testcase metadata saying if a testcase is favored
#[derive(Debug, Serialize, Deserialize)]
pub struct IsFavoredMetadata {}

crate::impl_serdeany!(IsFavoredMetadata);

/// A state metadata holding a map of favoreds testcases for each map entry
#[derive(Debug, Serialize, Deserialize)]
pub struct TopRatedsMetadata {
    /// map index -> corpus index
    pub map: HashMap<usize, CorpusId>,
}

crate::impl_serdeany!(TopRatedsMetadata);

impl TopRatedsMetadata {
    /// Creates a new [`struct@TopRatedsMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }

    /// Getter for map
    #[must_use]
    pub fn map(&self) -> &HashMap<usize, CorpusId> {
        &self.map
    }
}

impl Default for TopRatedsMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// The [`MinimizerScheduler`] employs a genetic algorithm to compute a subset of the
/// corpus that exercise all the requested features (e.g. all the coverage seen so far)
/// prioritizing [`Testcase`]`s` using [`TestcaseScore`]
#[derive(Debug, Clone)]
pub struct MinimizerScheduler<CS, F, M> {
    base: CS,
    skip_non_favored_prob: u64,
    phantom: PhantomData<(F, M)>,
}

impl<CS, F, M> UsesState for MinimizerScheduler<CS, F, M>
where
    CS: UsesState,
{
    type State = CS::State;
}

impl<CS, F, M> RemovableScheduler for MinimizerScheduler<CS, F, M>
where
    CS: RemovableScheduler,
    F: TestcaseScore<CS::State>,
    M: AsSlice<Entry = usize> + SerdeAny + HasRefCnt,
    CS::State: HasCorpus + HasMetadata + HasRand,
{
    /// Replaces the testcase at the given idx
    fn on_replace(
        &mut self,
        state: &mut CS::State,
        idx: CorpusId,
        testcase: &Testcase<<CS::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        self.base.on_replace(state, idx, testcase)?;
        self.update_score(state, idx)
    }

    /// Removes an entry from the corpus, returning M if M was present.
    fn on_remove(
        &mut self,
        state: &mut CS::State,
        idx: CorpusId,
        testcase: &Option<Testcase<<CS::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        self.base.on_remove(state, idx, testcase)?;
        let mut entries =
            if let Some(meta) = state.metadata_map_mut().get_mut::<TopRatedsMetadata>() {
                let entries = meta
                    .map
                    .drain_filter(|_, other_idx| *other_idx == idx)
                    .map(|(entry, _)| entry)
                    .collect::<Vec<_>>();
                entries
            } else {
                return Ok(());
            };
        entries.sort_unstable(); // this should already be sorted, but just in case
        let mut map = HashMap::new();
        for i in state.corpus().ids() {
            let mut old = state.corpus().get(i)?.borrow_mut();
            let factor = F::compute(state, &mut *old)?;
            if let Some(old_map) = old.metadata_map_mut().get_mut::<M>() {
                let mut e_iter = entries.iter();
                let mut map_iter = old_map.as_slice().iter(); // ASSERTION: guaranteed to be in order?

                // manual set intersection
                let mut entry = e_iter.next();
                let mut map_entry = map_iter.next();
                while let Some(e) = entry {
                    if let Some(me) = map_entry {
                        match e.cmp(me) {
                            Ordering::Less => {
                                entry = e_iter.next();
                            }
                            Ordering::Equal => {
                                // if we found a better factor, prefer it
                                map.entry(*e)
                                    .and_modify(|(f, idx)| {
                                        if *f > factor {
                                            *f = factor;
                                            *idx = i;
                                        }
                                    })
                                    .or_insert((factor, i));
                                entry = e_iter.next();
                                map_entry = map_iter.next();
                            }
                            Ordering::Greater => {
                                map_entry = map_iter.next();
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        if let Some(mut meta) = state.metadata_map_mut().remove::<TopRatedsMetadata>() {
            let map_iter = map.iter();

            let reserve = if meta.map.is_empty() {
                map_iter.size_hint().0
            } else {
                (map_iter.size_hint().0 + 1) / 2
            };
            meta.map.reserve(reserve);

            for (entry, (_, new_idx)) in map_iter {
                let mut new = state.corpus().get(*new_idx)?.borrow_mut();
                let new_meta = new.metadata_map_mut().get_mut::<M>().ok_or_else(|| {
                    Error::key_not_found(format!(
                        "{} needed for MinimizerScheduler not found in testcase #{new_idx}",
                        type_name::<M>()
                    ))
                })?;
                *new_meta.refcnt_mut() += 1;
                meta.map.insert(*entry, *new_idx);
            }

            // Put back the metadata
            state.metadata_map_mut().insert_boxed(meta);
        }
        Ok(())
    }
}

impl<CS, F, M> Scheduler for MinimizerScheduler<CS, F, M>
where
    CS: Scheduler,
    F: TestcaseScore<CS::State>,
    M: AsSlice<Entry = usize> + SerdeAny + HasRefCnt,
    CS::State: HasCorpus + HasMetadata + HasRand,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&mut self, state: &mut CS::State, idx: CorpusId) -> Result<(), Error> {
        self.base.on_add(state, idx)?;
        self.update_score(state, idx)
    }

    /// An input has been evaluated
    fn on_evaluation<OT>(
        &mut self,
        state: &mut Self::State,
        input: &<Self::State as UsesInput>::Input,
        observers: &OT,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<Self::State>,
    {
        self.base.on_evaluation(state, input, observers)
    }

    /// Gets the next entry
    fn next(&mut self, state: &mut CS::State) -> Result<CorpusId, Error> {
        self.cull(state)?;
        let mut idx = self.base.next(state)?;
        while {
            let has = !state
                .corpus()
                .get(idx)?
                .borrow()
                .has_metadata::<IsFavoredMetadata>();
            has
        } && state.rand_mut().below(100) < self.skip_non_favored_prob
        {
            idx = self.base.next(state)?;
        }
        Ok(idx)
    }

    /// Set current fuzzed corpus id and `scheduled_count`
    fn set_current_scheduled(
        &mut self,
        _state: &mut Self::State,
        _next_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        // We do nothing here, the inner scheduler will take care of it
        Ok(())
    }
}

impl<CS, F, M> MinimizerScheduler<CS, F, M>
where
    CS: Scheduler,
    F: TestcaseScore<CS::State>,
    M: AsSlice<Entry = usize> + SerdeAny + HasRefCnt,
    CS::State: HasCorpus + HasMetadata + HasRand,
{
    /// Update the `Corpus` score using the `MinimizerScheduler`
    #[allow(clippy::unused_self)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn update_score(&self, state: &mut CS::State, idx: CorpusId) -> Result<(), Error> {
        // Create a new top rated meta if not existing
        if state.metadata_map().get::<TopRatedsMetadata>().is_none() {
            state.add_metadata(TopRatedsMetadata::new());
        }

        let mut new_favoreds = vec![];
        {
            let mut entry = state.corpus().get(idx)?.borrow_mut();
            let factor = F::compute(state, &mut *entry)?;
            let meta = entry.metadata_map_mut().get_mut::<M>().ok_or_else(|| {
                Error::key_not_found(format!(
                    "Metadata needed for MinimizerScheduler not found in testcase #{idx}"
                ))
            })?;
            let top_rateds = state.metadata_map().get::<TopRatedsMetadata>().unwrap();
            for elem in meta.as_slice() {
                if let Some(old_idx) = top_rateds.map.get(elem) {
                    if *old_idx == idx {
                        new_favoreds.push(*elem); // always retain current; we'll drop it later otherwise
                        continue;
                    }
                    let mut old = state.corpus().get(*old_idx)?.borrow_mut();
                    if factor > F::compute(state, &mut *old)? {
                        continue;
                    }

                    let must_remove = {
                        let old_meta = old.metadata_map_mut().get_mut::<M>().ok_or_else(|| {
                            Error::key_not_found(format!(
                                "{} needed for MinimizerScheduler not found in testcase #{old_idx}",
                                type_name::<M>()
                            ))
                        })?;
                        *old_meta.refcnt_mut() -= 1;
                        old_meta.refcnt() <= 0
                    };

                    if must_remove {
                        drop(old.metadata_map_mut().remove::<M>());
                    }
                }

                new_favoreds.push(*elem);
            }

            *meta.refcnt_mut() = new_favoreds.len() as isize;
        }

        if new_favoreds.is_empty() {
            drop(
                state
                    .corpus()
                    .get(idx)?
                    .borrow_mut()
                    .metadata_map_mut()
                    .remove::<M>(),
            );
            return Ok(());
        }

        for elem in new_favoreds {
            state
                .metadata_map_mut()
                .get_mut::<TopRatedsMetadata>()
                .unwrap()
                .map
                .insert(elem, idx);
        }
        Ok(())
    }

    /// Cull the `Corpus` using the `MinimizerScheduler`
    #[allow(clippy::unused_self)]
    pub fn cull(&self, state: &mut CS::State) -> Result<(), Error> {
        let Some(top_rated) = state.metadata_map().get::<TopRatedsMetadata>() else { return Ok(()) };

        let mut acc = HashSet::new();

        for (key, idx) in &top_rated.map {
            if !acc.contains(key) {
                let mut entry = state.corpus().get(*idx)?.borrow_mut();
                let meta = entry.metadata_map().get::<M>().ok_or_else(|| {
                    Error::key_not_found(format!(
                        "{} needed for MinimizerScheduler not found in testcase #{idx}",
                        type_name::<M>()
                    ))
                })?;
                for elem in meta.as_slice() {
                    acc.insert(*elem);
                }

                entry.add_metadata(IsFavoredMetadata {});
            }
        }

        Ok(())
    }

    /// Get a reference to the base scheduler
    pub fn base(&self) -> &CS {
        &self.base
    }

    /// Get a reference to the base scheduler (mut)
    pub fn base_mut(&mut self) -> &mut CS {
        &mut self.base
    }

    /// Creates a new [`MinimizerScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a default probability to skip non-faved [`Testcase`]s of [`DEFAULT_SKIP_NON_FAVORED_PROB`].
    pub fn new(base: CS) -> Self {
        Self {
            base,
            skip_non_favored_prob: DEFAULT_SKIP_NON_FAVORED_PROB,
            phantom: PhantomData,
        }
    }

    /// Creates a new [`MinimizerScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a non-default probability to skip non-faved [`Testcase`]s using (`skip_non_favored_prob`).
    pub fn with_skip_prob(base: CS, skip_non_favored_prob: u64) -> Self {
        Self {
            base,
            skip_non_favored_prob,
            phantom: PhantomData,
        }
    }
}

/// A [`MinimizerScheduler`] with [`LenTimeMulTestcaseScore`] to prioritize quick and small [`Testcase`]`s`.
pub type LenTimeMinimizerScheduler<CS, M> =
    MinimizerScheduler<CS, LenTimeMulTestcaseScore<<CS as UsesState>::State>, M>;

/// A [`MinimizerScheduler`] with [`LenTimeMulTestcaseScore`] to prioritize quick and small [`Testcase`]`s`
/// that exercise all the entries registered in the [`MapIndexesMetadata`].
pub type IndexesLenTimeMinimizerScheduler<CS> =
    MinimizerScheduler<CS, LenTimeMulTestcaseScore<<CS as UsesState>::State>, MapIndexesMetadata>;
