//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use core::marker::PhantomData;
use std::prelude::v1::Vec;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::rands::Rand,
    corpus::Corpus,
    fuzzer::Evaluator,
    mark_feature_time,
    mutators::Mutator,
    observers::UsesObservers,
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasRand, UsesState},
    AsyncEvaluator, Error,
};

// TODO multi mutators stage

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<E, EM, M, Z>: Stage<E, EM, Z>
where
    E: UsesState<State = EM::State>,
    M: Mutator<EM::State>,
    EM: UsesState,
    Z: UsesState<State = EM::State>,
    EM::State: HasClientPerfMonitor + HasCorpus,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut Self::State, corpus_idx: usize) -> Result<u64, Error>;

    /// Runs this (mutational) stage for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>
    where
        Z: Evaluator<E, EM>,
    {
        let num = self.iterations(state, corpus_idx)?;

        for i in 0..num {
            start_timer!(state);
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

            start_timer!(state);
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            // Time is measured directly the `evaluate_input` function
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }
        Ok(())
    }

    /// Runs this (mutational) stage for the given testcase asynchronously
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational_async(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>
    where
        E: UsesObservers<State = EM::State>,
        Z: AsyncEvaluator<E, EM, State = EM::State>,
    {
        let num = self.iterations(state, corpus_idx)?;
        let mut deferred = Vec::with_capacity(num as usize);

        for i in 0..num {
            start_timer!(state);
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

            start_timer!(state);
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            // Time is measured directly the `evaluate_input` function
            let current = fuzzer.start_evaluate_input(state, executor, manager, &input)?;
            deferred.push((input, current));
        }

        for (i, (input, current)) in deferred.into_iter().enumerate() {
            let (_, _, corpus_idx) =
                fuzzer.complete_evaluation(state, executor, manager, input, current, true)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
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
pub struct StdMutationalStage<E, EM, M, Z, const ASYNC: bool> {
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, M, Z, const ASYNC: bool> MutationalStage<E, EM, M, Z>
    for StdMutationalStage<E, EM, M, Z, ASYNC>
where
    Self: Stage<E, EM, Z>, // band-aid; const generics can't tell if all cases are covered!
    E: UsesState,
    EM: UsesState<State = E::State>,
    M: Mutator<E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasClientPerfMonitor + HasCorpus + HasRand,
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
    fn iterations(&self, state: &mut Z::State, _corpus_idx: usize) -> Result<u64, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS))
    }
}

impl<E, EM, M, Z, const ASYNC: bool> UsesState for StdMutationalStage<E, EM, M, Z, ASYNC>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: UsesState,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, M, Z> Stage<E, EM, Z> for StdMutationalStage<E, EM, M, Z, false>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, M, Z> Stage<E, EM, Z> for StdMutationalStage<E, EM, M, Z, true>
where
    E: UsesObservers<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: AsyncEvaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Z::State,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational_async(fuzzer, executor, state, manager, corpus_idx);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }
}

impl<E, EM, M, Z> StdMutationalStage<E, EM, M, Z, false>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}

impl<E, EM, M, Z> StdMutationalStage<E, EM, M, Z, true>
where
    E: UsesObservers<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::State>,
    Z: AsyncEvaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand,
{
    /// Creates a new default mutational stage
    pub fn new_async(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
/// `StdMutationalStage` Python bindings
pub mod pybind {
    use pyo3::prelude::*;

    use crate::{
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        fuzzer::pybind::PythonStdFuzzer,
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
            PythonMutator,
            PythonStdFuzzer,
            false,
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
