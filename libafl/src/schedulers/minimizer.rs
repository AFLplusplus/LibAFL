//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer
//! with testcases only from a subset of the total corpus.

use alloc::vec::Vec;
use core::{cmp::Ordering, marker::PhantomData};

use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{rands::Rand, serdeany::SerdeAny, AsSlice, HasRefCnt},
    corpus::{Corpus, Testcase},
    feedbacks::MapIndexesMetadata,
    inputs::UsesInput,
    schedulers::{LenTimeMulTestcaseScore, Scheduler, TestcaseScore},
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
    pub map: HashMap<usize, usize>,
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
    pub fn map(&self) -> &HashMap<usize, usize> {
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

impl<CS, F, M> Scheduler for MinimizerScheduler<CS, F, M>
where
    CS: Scheduler,
    F: TestcaseScore<CS::State>,
    M: AsSlice<Entry = usize> + SerdeAny + HasRefCnt,
    CS::State: HasCorpus + HasMetadata + HasRand,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut CS::State, idx: usize) -> Result<(), Error> {
        self.update_score(state, idx)?;
        self.base.on_add(state, idx)
    }

    /// Replaces the testcase at the given idx
    fn on_replace(
        &self,
        state: &mut CS::State,
        idx: usize,
        testcase: &Testcase<<CS::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        self.update_score(state, idx)?;
        self.base.on_replace(state, idx, testcase)
    }

    /// Removes an entry from the corpus, returning M if M was present.
    fn on_remove(
        &self,
        state: &mut CS::State,
        idx: usize,
        testcase: &Option<Testcase<<CS::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        self.base.on_remove(state, idx, testcase)?;
        let mut entries = if let Some(meta) = state.metadata_mut().get_mut::<TopRatedsMetadata>() {
            let entries = meta
                .map
                .drain_filter(|_, other_idx| *other_idx == idx)
                .map(|(entry, _)| entry)
                .collect::<Vec<_>>();
            meta.map
                .values_mut()
                .filter(|other_idx| **other_idx > idx)
                .for_each(|other_idx| {
                    *other_idx -= 1;
                });
            entries
        } else {
            return Ok(());
        };
        entries.sort_unstable(); // this should already be sorted, but just in case
        let mut map = HashMap::new();
        for i in 0..state.corpus().count() {
            let mut old = state.corpus().get(i)?.borrow_mut();
            let factor = F::compute(&mut *old, state)?;
            if let Some(old_map) = old.metadata_mut().get_mut::<M>() {
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
        if let Some(meta) = state.metadata_mut().get_mut::<TopRatedsMetadata>() {
            meta.map
                .extend(map.into_iter().map(|(entry, (_, idx))| (entry, idx)));
        }
        Ok(())
    }

    /// Gets the next entry
    fn next(&self, state: &mut CS::State) -> Result<usize, Error> {
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
    pub fn update_score(&self, state: &mut CS::State, idx: usize) -> Result<(), Error> {
        // Create a new top rated meta if not existing
        if state.metadata().get::<TopRatedsMetadata>().is_none() {
            state.add_metadata(TopRatedsMetadata::new());
        }

        let mut new_favoreds = vec![];
        {
            let mut entry = state.corpus().get(idx)?.borrow_mut();
            let factor = F::compute(&mut *entry, state)?;
            let meta = entry.metadata_mut().get_mut::<M>().ok_or_else(|| {
                Error::key_not_found(format!(
                    "Metadata needed for MinimizerScheduler not found in testcase #{idx}"
                ))
            })?;
            for elem in meta.as_slice() {
                if let Some(old_idx) = state
                    .metadata()
                    .get::<TopRatedsMetadata>()
                    .unwrap()
                    .map
                    .get(elem)
                {
                    let mut old = state.corpus().get(*old_idx)?.borrow_mut();
                    if factor > F::compute(&mut *old, state)? {
                        continue;
                    }

                    let must_remove = {
                        let old_meta = old.metadata_mut().get_mut::<M>().ok_or_else(|| {
                            Error::key_not_found(format!(
                                "Metadata needed for MinimizerScheduler not found in testcase #{old_idx}"
                            ))
                        })?;
                        *old_meta.refcnt_mut() -= 1;
                        old_meta.refcnt() <= 0
                    };

                    if must_remove {
                        drop(old.metadata_mut().remove::<M>());
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
                    .metadata_mut()
                    .remove::<M>(),
            );
            return Ok(());
        }

        for elem in new_favoreds {
            state
                .metadata_mut()
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
        let Some(top_rated) = state.metadata().get::<TopRatedsMetadata>() else { return Ok(()) };

        let mut acc = HashSet::new();

        for (key, idx) in &top_rated.map {
            if !acc.contains(key) {
                let mut entry = state.corpus().get(*idx)?.borrow_mut();
                let meta = entry.metadata().get::<M>().ok_or_else(|| {
                    Error::key_not_found(format!(
                        "Metadata needed for MinimizerScheduler not found in testcase #{idx}"
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
