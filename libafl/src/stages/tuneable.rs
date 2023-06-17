//! A [`crate::stages::MutationalStage`] where the mutator iteration can be tuned at runtime

use core::{marker::PhantomData, time::Duration};

use serde::{Deserialize, Serialize};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::{current_time, rands::Rand},
    corpus::{Corpus, CorpusId},
    impl_serdeany, mark_feature_time,
    mutators::{MutationResult, Mutator},
    stages::{
        mutational::{MutatedTransform, MutatedTransformPost, DEFAULT_MUTATIONAL_MAX_ITERATIONS},
        MutationalStage, Stage,
    },
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasMetadata, HasRand, UsesState},
    Error, Evaluator,
};

#[derive(Default, Clone, Copy, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct TuneableMutationalStageMetadata {
    iters: Option<u64>,
    fuzz_time: Option<Duration>,
}

impl_serdeany!(TuneableMutationalStageMetadata);

/// Set the number of iterations to be used by this mutational stage
pub fn set_iters<S: HasMetadata>(state: &mut S, iters: u64) -> Result<(), Error> {
    let metadata = state
        .metadata_map_mut()
        .get_mut::<TuneableMutationalStageMetadata>()
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"));
    metadata.map(|metadata| {
        metadata.iters = Some(iters);
    })
}

/// Get the set iterations
pub fn get_iters<S: HasMetadata>(state: &S) -> Result<Option<u64>, Error> {
    state
        .metadata_map()
        .get::<TuneableMutationalStageMetadata>()
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"))
        .map(|metadata| metadata.iters)
}

/// Set the time for a single seed to be used by this mutational stage
pub fn set_seed_fuzz_time<S: HasMetadata>(state: &mut S, fuzz_time: Duration) -> Result<(), Error> {
    let metadata = state
        .metadata_map_mut()
        .get_mut::<TuneableMutationalStageMetadata>()
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"));
    metadata.map(|metadata| {
        metadata.fuzz_time = Some(fuzz_time);
    })
}

/// Get the time for a single seed to be used by this mutational stage
pub fn get_seed_fuzz_time<S: HasMetadata>(state: &mut S) -> Result<Option<Duration>, Error> {
    state
        .metadata_map()
        .get::<TuneableMutationalStageMetadata>()
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"))
        .map(|metadata| metadata.fuzz_time)
}

/// Reset this to a normal, randomized, stage
pub fn reset<S: HasMetadata>(state: &mut S) -> Result<(), Error> {
    state
        .metadata_map_mut()
        .get_mut::<TuneableMutationalStageMetadata>()
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"))
        .map(|metadata| {
            metadata.iters = None;
            metadata.fuzz_time = None;
        })
}

/// A [`crate::stages::MutationalStage`] where the mutator iteration can be tuned at runtime
#[derive(Clone, Debug)]
pub struct TuneableMutationalStage<E, EM, I, M, Z> {
    mutator: M,
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
{
    /// Runs this (mutational) stage for the given `testcase`
    /// Exactly the same functionality as [`MutationalStage::perform_mutational`], but with added timeout support.
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let metadata: &TuneableMutationalStageMetadata = state.metadata()?;

        let fuzz_time = metadata.fuzz_time;
        let iters = metadata.iters;

        let (start_time, iters) = if fuzz_time.is_some() {
            (Some(current_time()), iters)
        } else {
            (None, Some(self.iterations(state, corpus_idx)?))
        };

        start_timer!(state);
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let Ok(input) = I::try_transform_from(&mut testcase, state, corpus_idx) else { return Ok(()); };
        drop(testcase);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        let mut i = 0_usize;
        loop {
            if let Some(start_time) = start_time {
                if current_time() - start_time >= fuzz_time.unwrap() {
                    break;
                }
            }
            if let Some(iters) = iters {
                if i >= iters as usize {
                    break;
                }
            } else {
                i += 1;
            }

            let mut input = input.clone();

            start_timer!(state);
            let mutated = self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            if mutated == MutationResult::Skipped {
                continue;
            }

            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = input.try_transform_into(state)?;
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            post.post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }
        Ok(())
    }

    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    #[allow(clippy::cast_possible_truncation)]
    fn iterations(&self, state: &mut Z::State, _corpus_idx: CorpusId) -> Result<u64, Error> {
        Ok(if let Some(iters) = get_iters(state)? {
            iters
        } else {
            // fall back to random
            1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS)
        })
    }
}

impl<E, EM, I, M, Z> UsesState for TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, M, Z> TuneableMutationalStage<E, EM, Z::Input, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::Input, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
{
    /// Creates a new default mutational stage
    #[must_use]
    pub fn new(state: &mut Z::State, mutator: M) -> Self {
        Self::transforming(state, mutator)
    }
}

impl TuneableMutationalStage<(), (), (), (), ()> {
    /// Set the number of iterations to be used by this mutational stage
    pub fn set_iters<S: HasMetadata>(state: &mut S, iters: u64) -> Result<(), Error> {
        set_iters(state, iters)
    }

    /// Get the set iterations
    pub fn iters<S: HasMetadata>(state: &S) -> Result<Option<u64>, Error> {
        get_iters(state)
    }

    /// Set the time to mutate a single input in this mutational stage
    pub fn set_seed_fuzz_time<S: HasMetadata>(
        state: &mut S,
        fuzz_time: Duration,
    ) -> Result<(), Error> {
        set_seed_fuzz_time(state, fuzz_time)
    }

    /// Set the time to mutate a single input in this mutational stage
    pub fn seed_fuzz_time<S: HasMetadata>(state: &mut S) -> Result<Option<Duration>, Error> {
        get_seed_fuzz_time(state)
    }
}

impl<E, EM, I, M, Z> TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasMetadata,
{
    /// Creates a new tranforming mutational stage
    #[must_use]
    pub fn transforming(state: &mut Z::State, mutator: M) -> Self {
        if !state.has_metadata::<TuneableMutationalStageMetadata>() {
            state.add_metadata(TuneableMutationalStageMetadata::default());
        }
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}
