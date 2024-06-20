//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer
//! with testcases only from a subset of the total corpus.

use alloc::vec::Vec;
use core::{any::type_name, cmp::Ordering, marker::PhantomData};

use hashbrown::{HashMap, HashSet};
use libafl_bolts::{rands::Rand, serdeany::SerdeAny, AsIter, HasRefCnt};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, Testcase},
    feedbacks::MapIndexesMetadata,
    inputs::UsesInput,
    observers::{CanTrack, ObserversTuple},
    require_index_tracking,
    schedulers::{LenTimeMulTestcaseScore, RemovableScheduler, Scheduler, TestcaseScore},
    state::{HasCorpus, HasRand, UsesState},
    Error, HasMetadata,
};

/// Default probability to skip the non-favored values
pub const DEFAULT_SKIP_NON_FAVORED_PROB: f64 = 0.95;

/// A testcase metadata saying if a testcase is favored
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct IsFavoredMetadata {}

libafl_bolts::impl_serdeany!(IsFavoredMetadata);

/// A state metadata holding a map of favoreds testcases for each map entry
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct TopRatedsMetadata {
    /// map index -> corpus index
    pub map: HashMap<usize, CorpusId>,
}

libafl_bolts::impl_serdeany!(TopRatedsMetadata);

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
pub struct MinimizerScheduler<CS, F, M, O> {
    base: CS,
    skip_non_favored_prob: f64,
    remove_metadata: bool,
    phantom: PhantomData<(F, M, O)>,
}

impl<CS, F, M, O> UsesState for MinimizerScheduler<CS, F, M, O>
where
    CS: UsesState,
{
    type State = CS::State;
}

impl<CS, F, M, O> RemovableScheduler for MinimizerScheduler<CS, F, M, O>
where
    CS: RemovableScheduler,
    F: TestcaseScore<<Self as UsesState>::State>,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,
    <Self as UsesState>::State: HasCorpus + HasMetadata + HasRand,
    O: CanTrack,
{
    /// Replaces the testcase at the given id
    fn on_replace(
        &mut self,
        state: &mut <Self as UsesState>::State,
        id: CorpusId,
        testcase: &Testcase<<<Self as UsesState>::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        self.base.on_replace(state, id, testcase)?;
        self.update_score(state, id)
    }

    /// Removes an entry from the corpus
    fn on_remove(
        &mut self,
        state: &mut <Self as UsesState>::State,
        id: CorpusId,
        testcase: &Option<Testcase<<<Self as UsesState>::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        self.base.on_remove(state, id, testcase)?;
        let mut entries =
            if let Some(meta) = state.metadata_map_mut().get_mut::<TopRatedsMetadata>() {
                let entries = meta
                    .map
                    .extract_if(|_, other_id| *other_id == id)
                    .map(|(entry, _)| entry)
                    .collect::<Vec<_>>();
                entries
            } else {
                return Ok(());
            };
        entries.sort_unstable(); // this should already be sorted, but just in case
        let mut map = HashMap::new();
        for current_id in state.corpus().ids() {
            let mut old = state.corpus().get(current_id)?.borrow_mut();
            let factor = F::compute(state, &mut *old)?;
            if let Some(old_map) = old.metadata_map_mut().get_mut::<M>() {
                let mut e_iter = entries.iter();
                let mut map_iter = old_map.as_iter(); // ASSERTION: guaranteed to be in order?

                // manual set intersection
                let mut entry = e_iter.next();
                let mut map_entry = map_iter.next();
                while let Some(e) = entry {
                    if let Some(ref me) = map_entry {
                        match e.cmp(me) {
                            Ordering::Less => {
                                entry = e_iter.next();
                            }
                            Ordering::Equal => {
                                // if we found a better factor, prefer it
                                map.entry(*e)
                                    .and_modify(|(f, id)| {
                                        if *f > factor {
                                            *f = factor;
                                            *id = current_id;
                                        }
                                    })
                                    .or_insert((factor, current_id));
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

            for (entry, (_, new_id)) in map_iter {
                let mut new = state.corpus().get(*new_id)?.borrow_mut();
                let new_meta = new.metadata_map_mut().get_mut::<M>().ok_or_else(|| {
                    Error::key_not_found(format!(
                        "{} needed for MinimizerScheduler not found in testcase #{new_id}",
                        type_name::<M>()
                    ))
                })?;
                *new_meta.refcnt_mut() += 1;
                meta.map.insert(*entry, *new_id);
            }

            // Put back the metadata
            state.metadata_map_mut().insert_boxed(meta);
        }
        Ok(())
    }
}

impl<CS, F, M, O> Scheduler for MinimizerScheduler<CS, F, M, O>
where
    CS: Scheduler,
    F: TestcaseScore<Self::State>,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,
    Self::State: HasCorpus + HasMetadata + HasRand,
    O: CanTrack,
{
    /// Called when a [`Testcase`] is added to the corpus
    fn on_add(&mut self, state: &mut Self::State, id: CorpusId) -> Result<(), Error> {
        self.base.on_add(state, id)?;
        self.update_score(state, id)
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
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        self.cull(state)?;
        let mut id = self.base.next(state)?;
        while {
            let has = !state
                .corpus()
                .get(id)?
                .borrow()
                .has_metadata::<IsFavoredMetadata>();
            has
        } && state.rand_mut().coinflip(self.skip_non_favored_prob)
        {
            id = self.base.next(state)?;
        }
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

impl<CS, F, M, O> MinimizerScheduler<CS, F, M, O>
where
    CS: Scheduler,
    F: TestcaseScore<<Self as UsesState>::State>,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,
    <Self as UsesState>::State: HasCorpus + HasMetadata + HasRand,
    O: CanTrack,
{
    /// Update the [`Corpus`] score using the [`MinimizerScheduler`]
    #[allow(clippy::unused_self)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn update_score(
        &self,
        state: &mut <Self as UsesState>::State,
        id: CorpusId,
    ) -> Result<(), Error> {
        // Create a new top rated meta if not existing
        if state.metadata_map().get::<TopRatedsMetadata>().is_none() {
            state.add_metadata(TopRatedsMetadata::new());
        }

        let mut new_favoreds = vec![];
        {
            let mut entry = state.corpus().get(id)?.borrow_mut();
            let factor = F::compute(state, &mut *entry)?;
            let meta = entry.metadata_map_mut().get_mut::<M>().ok_or_else(|| {
                Error::key_not_found(format!(
                    "Metadata needed for MinimizerScheduler not found in testcase #{id}"
                ))
            })?;
            let top_rateds = state.metadata_map().get::<TopRatedsMetadata>().unwrap();
            for elem in meta.as_iter() {
                if let Some(old_id) = top_rateds.map.get(&*elem) {
                    if *old_id == id {
                        new_favoreds.push(*elem); // always retain current; we'll drop it later otherwise
                        continue;
                    }
                    let mut old = state.corpus().get(*old_id)?.borrow_mut();
                    if factor > F::compute(state, &mut *old)? {
                        continue;
                    }

                    let must_remove = {
                        let old_meta = old.metadata_map_mut().get_mut::<M>().ok_or_else(|| {
                            Error::key_not_found(format!(
                                "{} needed for MinimizerScheduler not found in testcase #{old_id}",
                                type_name::<M>()
                            ))
                        })?;
                        *old_meta.refcnt_mut() -= 1;
                        old_meta.refcnt() <= 0
                    };

                    if must_remove && self.remove_metadata {
                        drop(old.metadata_map_mut().remove::<M>());
                    }
                }

                new_favoreds.push(*elem);
            }

            *meta.refcnt_mut() = new_favoreds.len() as isize;
        }

        if new_favoreds.is_empty() && self.remove_metadata {
            drop(
                state
                    .corpus()
                    .get(id)?
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
                .insert(elem, id);
        }
        Ok(())
    }

    /// Cull the [`Corpus`] using the [`MinimizerScheduler`]
    #[allow(clippy::unused_self)]
    pub fn cull(&self, state: &<Self as UsesState>::State) -> Result<(), Error> {
        let Some(top_rated) = state.metadata_map().get::<TopRatedsMetadata>() else {
            return Ok(());
        };

        let mut acc = HashSet::new();

        for (key, id) in &top_rated.map {
            if !acc.contains(key) {
                let mut entry = state.corpus().get(*id)?.borrow_mut();
                let meta = entry.metadata_map().get::<M>().ok_or_else(|| {
                    Error::key_not_found(format!(
                        "{} needed for MinimizerScheduler not found in testcase #{id}",
                        type_name::<M>()
                    ))
                })?;
                for elem in meta.as_iter() {
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
    /// This will remove the metadata `M` when it is no longer needed, after consumption. This might
    /// for example be a `MapIndexesMetadata`.
    ///
    /// When calling, pass the edges observer which will provided the indexes to minimize over.
    pub fn new(_observer: &O, base: CS) -> Self {
        require_index_tracking!("MinimizerScheduler", O);
        Self {
            base,
            skip_non_favored_prob: DEFAULT_SKIP_NON_FAVORED_PROB,
            remove_metadata: true,
            phantom: PhantomData,
        }
    }

    /// Creates a new [`MinimizerScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a default probability to skip non-faved [`Testcase`]s of [`DEFAULT_SKIP_NON_FAVORED_PROB`].
    /// This method will prevent the metadata `M` from being removed at the end of scoring.
    ///
    /// When calling, pass the edges observer which will provided the indexes to minimize over.
    pub fn non_metadata_removing(_observer: &O, base: CS) -> Self {
        require_index_tracking!("MinimizerScheduler", O);
        Self {
            base,
            skip_non_favored_prob: DEFAULT_SKIP_NON_FAVORED_PROB,
            remove_metadata: false,
            phantom: PhantomData,
        }
    }

    /// Creates a new [`MinimizerScheduler`] that wraps a `base` [`Scheduler`]
    /// and has a non-default probability to skip non-faved [`Testcase`]s using (`skip_non_favored_prob`).
    ///
    /// When calling, pass the edges observer which will provided the indexes to minimize over.
    pub fn with_skip_prob(_observer: &O, base: CS, skip_non_favored_prob: f64) -> Self {
        require_index_tracking!("MinimizerScheduler", O);
        Self {
            base,
            skip_non_favored_prob,
            remove_metadata: true,
            phantom: PhantomData,
        }
    }
}

/// A [`MinimizerScheduler`] with [`LenTimeMulTestcaseScore`] to prioritize quick and small [`Testcase`]`s`.
pub type LenTimeMinimizerScheduler<CS, M, O> =
    MinimizerScheduler<CS, LenTimeMulTestcaseScore<<CS as UsesState>::State>, M, O>;

/// A [`MinimizerScheduler`] with [`LenTimeMulTestcaseScore`] to prioritize quick and small [`Testcase`]`s`
/// that exercise all the entries registered in the [`MapIndexesMetadata`].
pub type IndexesLenTimeMinimizerScheduler<CS, O> = MinimizerScheduler<
    CS,
    LenTimeMulTestcaseScore<<CS as UsesState>::State>,
    MapIndexesMetadata,
    O,
>;
