//! A [`crate::stages::MutationalStage`] where the mutator iteration can be tuned at runtime

use alloc::string::{String, ToString};
use core::{marker::PhantomData, time::Duration};

use libafl_bolts::{current_time, impl_serdeany, rands::Rand};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, HasCurrentCorpusIdx},
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    stages::{
        mutational::{MutatedTransform, MutatedTransformPost, DEFAULT_MUTATIONAL_MAX_ITERATIONS},
        ExecutionCountRestartHelper, MutationalStage, Stage,
    },
    start_timer,
    state::{HasCorpus, HasExecutions, HasMetadata, HasNamedMetadata, HasRand, UsesState},
    Error, Evaluator,
};
#[cfg(feature = "introspection")]
use crate::{monitors::PerfFeature, state::HasClientPerfMonitor};

#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Default, Clone, Copy, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct TuneableMutationalStageMetadata {
    iters: Option<u64>,
    fuzz_time: Option<Duration>,
}

impl_serdeany!(TuneableMutationalStageMetadata);

/// The default name of the tunenable mutational stage.
pub const STD_TUNEABLE_MUTATIONAL_STAGE_NAME: &str = "TuneableMutationalStage";

/// Set the number of iterations to be used by this mutational stage by name
pub fn set_iters_by_name<S>(state: &mut S, iters: u64, name: &str) -> Result<(), Error>
where
    S: HasNamedMetadata,
{
    let metadata = state
        .named_metadata_map_mut()
        .get_mut::<TuneableMutationalStageMetadata>(name)
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"));
    metadata.map(|metadata| {
        metadata.iters = Some(iters);
    })
}

/// Set the number of iterations to be used by this mutational stage with a default name
pub fn set_iters_std<S>(state: &mut S, iters: u64) -> Result<(), Error>
where
    S: HasNamedMetadata,
{
    set_iters_by_name(state, iters, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
}

/// Get the set iterations by name
pub fn get_iters_by_name<S>(state: &S, name: &str) -> Result<Option<u64>, Error>
where
    S: HasNamedMetadata,
{
    state
        .named_metadata_map()
        .get::<TuneableMutationalStageMetadata>(name)
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"))
        .map(|metadata| metadata.iters)
}

/// Get the set iterations with a default name
pub fn get_iters_std<S>(state: &S) -> Result<Option<u64>, Error>
where
    S: HasNamedMetadata,
{
    get_iters_by_name(state, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
}

/// Set the time for a single seed to be used by this mutational stage
pub fn set_seed_fuzz_time_by_name<S>(
    state: &mut S,
    fuzz_time: Duration,
    name: &str,
) -> Result<(), Error>
where
    S: HasNamedMetadata,
{
    let metadata = state
        .named_metadata_map_mut()
        .get_mut::<TuneableMutationalStageMetadata>(name)
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"));
    metadata.map(|metadata| {
        metadata.fuzz_time = Some(fuzz_time);
    })
}

/// Set the time for a single seed to be used by this mutational stage with a default name
pub fn set_seed_fuzz_time_std<S>(state: &mut S, fuzz_time: Duration) -> Result<(), Error>
where
    S: HasNamedMetadata,
{
    set_seed_fuzz_time_by_name(state, fuzz_time, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
}

/// Get the time for a single seed to be used by this mutational stage by name
pub fn get_seed_fuzz_time_by_name<S>(state: &S, name: &str) -> Result<Option<Duration>, Error>
where
    S: HasNamedMetadata,
{
    state
        .named_metadata_map()
        .get::<TuneableMutationalStageMetadata>(name)
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"))
        .map(|metadata| metadata.fuzz_time)
}

/// Get the time for a single seed to be used by this mutational stage with a default name
pub fn get_seed_fuzz_time_std<S>(state: &S) -> Result<Option<Duration>, Error>
where
    S: HasNamedMetadata,
{
    get_seed_fuzz_time_by_name(state, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
}

/// Reset this to a normal, randomized, stage by name
pub fn reset_by_name<S>(state: &mut S, name: &str) -> Result<(), Error>
where
    S: HasNamedMetadata,
{
    state
        .named_metadata_map_mut()
        .get_mut::<TuneableMutationalStageMetadata>(name)
        .ok_or_else(|| Error::illegal_state("TuneableMutationalStage not in use"))
        .map(|metadata| {
            metadata.iters = None;
            metadata.fuzz_time = None;
        })
}

/// Reset this to a normal, randomized, stage with a default name
pub fn reset_std<S>(state: &mut S) -> Result<(), Error>
where
    S: HasNamedMetadata,
{
    reset_by_name(state, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
}

/// A [`crate::stages::MutationalStage`] where the mutator iteration can be tuned at runtime
#[derive(Clone, Debug)]
pub struct TuneableMutationalStage<E, EM, I, M, Z> {
    /// The mutator we use
    mutator: M,
    /// The name of this stage
    name: String,
    /// The progress helper we use to keep track of progress across restarts
    restart_helper: ExecutionCountRestartHelper,
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasNamedMetadata + HasMetadata + HasExecutions,
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
    ) -> Result<(), Error> {
        let Some(corpus_idx) = state.current_corpus_idx()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };

        let fuzz_time = self.seed_fuzz_time(state)?;
        let iters = self.fixed_iters(state)?;

        start_timer!(state);
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let Ok(input) = I::try_transform_from(&mut testcase, state, corpus_idx) else {
            return Ok(());
        };
        drop(testcase);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        match (fuzz_time, iters) {
            (Some(fuzz_time), Some(iters)) => {
                // perform n iterations or fuzz for provided time, whichever comes first
                let start_time = current_time();
                for i in 1..=iters {
                    if current_time() - start_time >= fuzz_time {
                        break;
                    }

                    self.perform_mutation(fuzzer, executor, state, manager, &input, i)?;
                }
            }
            (Some(fuzz_time), None) => {
                // fuzz for provided time
                let start_time = current_time();
                for i in 1.. {
                    if current_time() - start_time >= fuzz_time {
                        break;
                    }

                    self.perform_mutation(fuzzer, executor, state, manager, &input, i)?;
                }
            }
            (None, Some(iters)) => {
                // perform n iterations
                for i in 1..=iters {
                    self.perform_mutation(fuzzer, executor, state, manager, &input, i)?;
                }
            }
            (None, None) => {
                // fall back to random
                let iters = self.iterations(state)? - self.execs_since_progress_start(state)?;
                for i in 1..=iters {
                    self.perform_mutation(fuzzer, executor, state, manager, &input, i)?;
                }
            }
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
    fn iterations(&self, state: &mut Z::State) -> Result<u64, Error> {
        Ok(
            // fall back to random
            1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS),
        )
    }

    fn execs_since_progress_start(&mut self, state: &mut <Z>::State) -> Result<u64, Error> {
        self.restart_helper.execs_since_progress_start(state)
    }
}

impl<E, EM, I, M, Z> UsesState for TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasExecutions,
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
    Z::State: HasCorpus + HasRand + HasNamedMetadata + HasMetadata + HasExecutions,
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
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        self.restart_helper.restart_progress_should_run(state)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.restart_helper.clear_restart_progress(state)
    }
}

impl<E, EM, I, M, Z> TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasNamedMetadata + HasMetadata + HasExecutions,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
{
    /// Creates a new default tuneable mutational stage
    #[must_use]
    pub fn new(state: &mut Z::State, mutator: M) -> Self {
        Self::transforming(state, mutator, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
    }

    /// Crates a new tuneable mutational stage with the given name
    pub fn with_name(state: &mut Z::State, mutator: M, name: &str) -> Self {
        Self::transforming(state, mutator, name)
    }

    /// Set the number of iterations to be used by this [`TuneableMutationalStage`]
    pub fn set_iters<S>(&self, state: &mut S, iters: u64) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        set_iters_by_name(state, iters, &self.name)
    }

    /// Set the number of iterations to be used by the std [`TuneableMutationalStage`]
    pub fn set_iters_std(state: &mut Z::State, iters: u64) -> Result<(), Error> {
        set_iters_by_name(state, iters, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
    }

    /// Set the number of iterations to be used by the [`TuneableMutationalStage`] with the given name
    pub fn set_iters_by_name<S>(state: &mut S, iters: u64, name: &str) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        set_iters_by_name(state, iters, name)
    }

    /// Get the set iterations for this [`TuneableMutationalStage`], if any
    pub fn fixed_iters<S>(&self, state: &S) -> Result<Option<u64>, Error>
    where
        S: HasNamedMetadata,
    {
        get_iters_by_name(state, &self.name)
    }

    /// Get the set iterations for the std [`TuneableMutationalStage`], if any
    pub fn iters_std(state: &Z::State) -> Result<Option<u64>, Error> {
        get_iters_by_name(state, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
    }

    /// Get the set iterations for the [`TuneableMutationalStage`] with the given name, if any
    pub fn iters_by_name<S>(state: &S, name: &str) -> Result<Option<u64>, Error>
    where
        S: HasNamedMetadata,
    {
        get_iters_by_name(state, name)
    }

    /// Set the time to mutate a single input in this [`TuneableMutationalStage`]
    pub fn set_seed_fuzz_time<S>(&self, state: &mut S, fuzz_time: Duration) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        set_seed_fuzz_time_by_name(state, fuzz_time, &self.name)
    }

    /// Set the time to mutate a single input in the std [`TuneableMutationalStage`]
    pub fn set_seed_fuzz_time_std(state: &mut Z::State, fuzz_time: Duration) -> Result<(), Error> {
        set_seed_fuzz_time_by_name(state, fuzz_time, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
    }

    /// Set the time to mutate a single input in the [`TuneableMutationalStage`] with the given name
    pub fn set_seed_fuzz_time_by_name<S>(
        state: &mut S,
        fuzz_time: Duration,
        name: &str,
    ) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        set_seed_fuzz_time_by_name(state, fuzz_time, name)
    }

    /// Set the time to mutate a single input in this [`TuneableMutationalStage`]
    pub fn seed_fuzz_time<S>(&self, state: &S) -> Result<Option<Duration>, Error>
    where
        S: HasNamedMetadata,
    {
        get_seed_fuzz_time_by_name(state, &self.name)
    }

    /// Set the time to mutate a single input for the std [`TuneableMutationalStage`]
    pub fn seed_fuzz_time_std(&self, state: &Z::State) -> Result<Option<Duration>, Error> {
        get_seed_fuzz_time_by_name(state, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
    }

    /// Set the time to mutate a single input for the [`TuneableMutationalStage`] with a given name
    pub fn seed_fuzz_time_by_name<S>(
        &self,
        state: &S,
        name: &str,
    ) -> Result<Option<Duration>, Error>
    where
        S: HasNamedMetadata,
    {
        get_seed_fuzz_time_by_name(state, name)
    }

    /// Reset this to a normal, randomized, stage with
    pub fn reset<S>(&self, state: &mut S) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        reset_by_name(state, &self.name)
    }

    /// Reset the std stage to a normal, randomized, stage
    pub fn reset_std(state: &mut Z::State) -> Result<(), Error> {
        reset_by_name(state, STD_TUNEABLE_MUTATIONAL_STAGE_NAME)
    }

    /// Reset this to a normal, randomized, stage by name
    pub fn reset_by_name<S>(state: &mut S, name: &str) -> Result<(), Error>
    where
        S: HasNamedMetadata,
    {
        reset_by_name(state, name)
    }

    fn perform_mutation(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        input: &I,
        stage_idx: u64,
    ) -> Result<(), Error> {
        let mut input = input.clone();

        start_timer!(state);
        let mutated = self
            .mutator_mut()
            .mutate(state, &mut input, stage_idx as i32)?;
        mark_feature_time!(state, PerfFeature::Mutate);

        if mutated == MutationResult::Skipped {
            return Ok(());
        }

        // Time is measured directly the `evaluate_input` function
        let (untransformed, post) = input.try_transform_into(state)?;
        let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;

        start_timer!(state);
        self.mutator_mut()
            .post_exec(state, stage_idx as i32, corpus_idx)?;
        post.post_exec(state, stage_idx as i32, corpus_idx)?;
        mark_feature_time!(state, PerfFeature::MutatePostExec);

        Ok(())
    }
}

impl<E, EM, I, M, Z> TuneableMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasNamedMetadata,
{
    /// Creates a new tranforming mutational stage
    #[must_use]
    pub fn transforming(state: &mut Z::State, mutator: M, name: &str) -> Self {
        let _ = state.named_metadata_or_insert_with(name, TuneableMutationalStageMetadata::default);
        Self {
            mutator,
            name: name.to_string(),
            restart_helper: ExecutionCountRestartHelper::default(),
            phantom: PhantomData,
        }
    }
}
