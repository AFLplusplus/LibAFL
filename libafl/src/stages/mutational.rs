//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use core::{any::type_name, marker::PhantomData};

use libafl_bolts::{rands::Rand, Named};

use crate::{
    corpus::{Corpus, CorpusId, Testcase},
    fuzzer::Evaluator,
    inputs::Input,
    mark_feature_time,
    mutators::{MultiMutator, MutationResult, Mutator},
    stages::{ExecutionCountRestartHelper, RetryRestartHelper, Stage},
    start_timer,
    state::{
        HasCorpus, HasCurrentTestcase, HasExecutions, HasMetadata, HasNamedMetadata, HasRand,
        UsesState,
    },
    Error,
};
#[cfg(feature = "introspection")]
use crate::{monitors::PerfFeature, state::HasClientPerfMonitor};

// TODO multi mutators stage

/// Action performed after the un-transformed input is executed (e.g., updating metadata)
#[allow(unused_variables)]
pub trait MutatedTransformPost<S>: Sized {
    /// Perform any post-execution steps necessary for the transformed input (e.g., updating metadata)
    #[inline]
    fn post_exec(self, state: &mut S, new_corpus_idx: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> MutatedTransformPost<S> for () {}

/// A type which may both be transformed from and into a given input type, used to perform
/// mutations over inputs which are not necessarily performable on the underlying type
///
/// This trait is implemented such that all testcases inherently transform to their inputs, should
/// the input be cloneable.
pub trait MutatedTransform<I, S>: Sized
where
    I: Input,
{
    /// Type indicating actions to be taken after the post-transformation input is executed
    type Post: MutatedTransformPost<S>;

    /// Transform the provided testcase into this type
    fn try_transform_from(base: &mut Testcase<I>, state: &S) -> Result<Self, Error>;

    /// Transform this instance back into the original input type
    fn try_transform_into(self, state: &S) -> Result<(I, Self::Post), Error>;
}

// reflexive definition
impl<I, S> MutatedTransform<I, S> for I
where
    I: Input + Clone,
    S: HasCorpus<Input = I>,
{
    type Post = ();

    #[inline]
    fn try_transform_from(base: &mut Testcase<I>, state: &S) -> Result<Self, Error> {
        state.corpus().load_input_into(base)?;
        Ok(base.input().as_ref().unwrap().clone())
    }

    #[inline]
    fn try_transform_into(self, _state: &S) -> Result<(I, Self::Post), Error> {
        Ok((self, ()))
    }
}

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<E, EM, I, M, Z>: Stage<E, EM, Z>
where
    E: UsesState<State = Self::State>,
    M: Mutator<I, Self::State>,
    EM: UsesState<State = Self::State>,
    Z: Evaluator<E, EM, State = Self::State>,
    Self::State: HasCorpus,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut Z::State) -> Result<u64, Error>;

    /// Gets the number of executions this mutator already did since it got first called in this fuzz round.
    fn execs_since_progress_start(&mut self, state: &mut Z::State) -> Result<u64, Error>;

    /// Runs this (mutational) stage for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        start_timer!(state);

        // Here saturating_sub is needed as self.iterations() might be actually smaller than the previous value before reset.
        let num = self
            .iterations(state)?
            .saturating_sub(self.execs_since_progress_start(state)?);
        let mut testcase = state.current_testcase_mut()?;

        let Ok(input) = I::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };
        drop(testcase);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        for _ in 0..num {
            let mut input = input.clone();

            start_timer!(state);
            let mutated = self.mutator_mut().mutate(state, &mut input)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            if mutated == MutationResult::Skipped {
                continue;
            }

            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = input.try_transform_into(state)?;
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, corpus_idx)?;
            post.post_exec(state, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }

        Ok(())
    }
}

/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct StdMutationalStage<E, EM, I, M, Z> {
    /// The mutator(s) to use
    mutator: M,
    /// The maximum amount of iterations we should do each round
    max_iterations: u64,
    /// The progress helper for this mutational stage
    restart_helper: ExecutionCountRestartHelper,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for StdMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasExecutions + HasMetadata,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
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
    fn iterations(&self, state: &mut Z::State) -> Result<u64, Error> {
        Ok(1 + state.rand_mut().below(self.max_iterations))
    }

    fn execs_since_progress_start(&mut self, state: &mut <Z>::State) -> Result<u64, Error> {
        self.restart_helper.execs_since_progress_start(state)
    }
}

impl<E, EM, I, M, Z> UsesState for StdMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for StdMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasMetadata + HasExecutions,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
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

impl<E, EM, M, Z> StdMutationalStage<E, EM, Z::Input, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::Input, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self::transforming_with_max_iterations(mutator, DEFAULT_MUTATIONAL_MAX_ITERATIONS)
    }

    /// Creates a new mutational stage with the given max iterations
    pub fn with_max_iterations(mutator: M, max_iterations: u64) -> Self {
        Self::transforming_with_max_iterations(mutator, max_iterations)
    }
}

impl<E, EM, I, M, Z> StdMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand,
{
    /// Creates a new transforming mutational stage with the default max iterations
    pub fn transforming(mutator: M) -> Self {
        Self::transforming_with_max_iterations(mutator, DEFAULT_MUTATIONAL_MAX_ITERATIONS)
    }

    /// Creates a new transforming mutational stage with the given max iterations
    pub fn transforming_with_max_iterations(mutator: M, max_iterations: u64) -> Self {
        Self {
            mutator,
            max_iterations,
            restart_helper: ExecutionCountRestartHelper::default(),
            phantom: PhantomData,
        }
    }
}

/// A mutational stage that operates on multiple inputs, as returned by [`MultiMutator::multi_mutate`].
#[derive(Clone, Debug)]
pub struct MultiMutationalStage<E, EM, I, M, Z> {
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> UsesState for MultiMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: MultiMutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> Named for MultiMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: MultiMutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand,
{
    fn name(&self) -> &str {
        type_name::<Self>()
    }
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for MultiMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: MultiMutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand + HasNamedMetadata,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    #[inline]
    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // TODO: add proper crash/timeout handling
        // For now, Make sure we don't get stuck crashing on a single testcase
        RetryRestartHelper::restart_progress_should_run(state, self, 3)
    }

    #[inline]
    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        RetryRestartHelper::clear_restart_progress(state, self)
    }

    #[inline]
    #[allow(clippy::let_and_return)]
    #[allow(clippy::cast_possible_wrap)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let mut testcase = state.current_testcase_mut()?;
        let Ok(input) = I::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };
        drop(testcase);

        let generated = self.mutator.multi_mutate(state, &input, None)?;
        // println!("Generated {}", generated.len());
        for new_input in generated {
            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = new_input.try_transform_into(state)?;
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
            self.mutator.multi_post_exec(state, corpus_idx)?;
            post.post_exec(state, corpus_idx)?;
        }
        // println!("Found {}", found);

        Ok(())
    }
}

impl<E, EM, M, Z> MultiMutationalStage<E, EM, Z::Input, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: MultiMutator<Z::Input, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand,
{
    /// Creates a new [`MultiMutationalStage`]
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, EM, I, M, Z> MultiMutationalStage<E, EM, I, M, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: MultiMutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasCorpus + HasRand,
{
    /// Creates a new transforming mutational stage
    pub fn transforming(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
#[allow(clippy::unnecessary_fallible_conversions, unused_qualifications)]
/// `StdMutationalStage` Python bindings
pub mod pybind {
    use pyo3::prelude::*;

    use crate::{
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        fuzzer::pybind::PythonStdFuzzer,
        inputs::BytesInput,
        mutators::pybind::PythonMutator,
        stages::{pybind::PythonStage, StdMutationalStage},
    };

    #[pyclass(unsendable, name = "StdMutationalStage")]
    #[derive(Debug)]
    /// Python class for StdMutationalStage
    pub struct PythonStdMutationalStage {
        /// Rust wrapped StdMutationalStage object
        pub inner: StdMutationalStage<
            PythonExecutor,
            PythonEventManager,
            BytesInput,
            PythonMutator,
            PythonStdFuzzer,
        >,
    }

    #[pymethods]
    impl PythonStdMutationalStage {
        #[new]
        fn new(mutator: PythonMutator) -> Self {
            Self {
                inner: StdMutationalStage::new(mutator),
            }
        }

        fn as_stage(slf: Py<Self>) -> PythonStage {
            PythonStage::new_std_mutational(slf)
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdMutationalStage>()?;
        Ok(())
    }
}
