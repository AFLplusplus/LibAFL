//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer
// with testcases only from a subset of the total corpus.

use crate::{
    bolts::{rands::Rand, serdeany::SerdeAny, AsSlice, HasRefCnt},
    corpus::{Corpus, Testcase},
    feedbacks::MapIndexesMetadata,
    inputs::Input,
    schedulers::{LenTimeMulTestcaseScore, Scheduler, TestcaseScore},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

use core::marker::PhantomData;
use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

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
pub struct MinimizerScheduler<CS, F, I, M, S>
where
    CS: Scheduler<I, S>,
    F: TestcaseScore<I, S>,
    I: Input,
    M: AsSlice<usize> + SerdeAny + HasRefCnt,
    S: HasCorpus<I> + HasMetadata,
{
    base: CS,
    skip_non_favored_prob: u64,
    phantom: PhantomData<(F, I, M, S)>,
}

impl<CS, F, I, M, S> Scheduler<I, S> for MinimizerScheduler<CS, F, I, M, S>
where
    CS: Scheduler<I, S>,
    F: TestcaseScore<I, S>,
    I: Input,
    M: AsSlice<usize> + SerdeAny + HasRefCnt,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        self.update_score(state, idx)?;
        self.base.on_add(state, idx)
    }

    /// Replaces the testcase at the given idx
    fn on_replace(&self, state: &mut S, idx: usize, testcase: &Testcase<I>) -> Result<(), Error> {
        self.base.on_replace(state, idx, testcase)
    }

    /// Removes an entry from the corpus, returning M if M was present.
    fn on_remove(
        &self,
        state: &mut S,
        idx: usize,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        self.base.on_remove(state, idx, testcase)
    }

    /// Gets the next entry
    fn next(&self, state: &mut S) -> Result<usize, Error> {
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

impl<CS, F, I, M, S> MinimizerScheduler<CS, F, I, M, S>
where
    CS: Scheduler<I, S>,
    F: TestcaseScore<I, S>,
    I: Input,
    M: AsSlice<usize> + SerdeAny + HasRefCnt,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    /// Update the `Corpus` score using the `MinimizerScheduler`
    #[allow(clippy::unused_self)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn update_score(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        // Create a new top rated meta if not existing
        if state.metadata().get::<TopRatedsMetadata>().is_none() {
            state.add_metadata(TopRatedsMetadata::new());
        }

        let mut new_favoreds = vec![];
        {
            let mut entry = state.corpus().get(idx)?.borrow_mut();
            let factor = F::compute(&mut *entry, state)?;
            let meta = entry.metadata_mut().get_mut::<M>().ok_or_else(|| {
                Error::KeyNotFound(format!(
                    "Metadata needed for MinimizerScheduler not found in testcase #{}",
                    idx
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
                            Error::KeyNotFound(format!(
                                "Metadata needed for MinimizerScheduler not found in testcase #{}",
                                old_idx
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
    pub fn cull(&self, state: &mut S) -> Result<(), Error> {
        let top_rated = match state.metadata().get::<TopRatedsMetadata>() {
            None => return Ok(()),
            Some(val) => val,
        };

        let mut acc = HashSet::new();

        for (key, idx) in &top_rated.map {
            if !acc.contains(key) {
                let mut entry = state.corpus().get(*idx)?.borrow_mut();
                let meta = entry.metadata().get::<M>().ok_or_else(|| {
                    Error::KeyNotFound(format!(
                        "Metadata needed for MinimizerScheduler not found in testcase #{}",
                        idx
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
pub type LenTimeMinimizerScheduler<CS, I, M, S> =
    MinimizerScheduler<CS, LenTimeMulTestcaseScore<I, S>, I, M, S>;

/// A [`MinimizerScheduler`] with [`LenTimeMulTestcaseScore`] to prioritize quick and small [`Testcase`]`s`
/// that exercise all the entries registered in the [`MapIndexesMetadata`].
pub type IndexesLenTimeMinimizerScheduler<CS, I, S> =
    MinimizerScheduler<CS, LenTimeMulTestcaseScore<I, S>, I, MapIndexesMetadata, S>;
