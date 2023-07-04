//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use core::marker::PhantomData;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, CorpusId, Testcase},
    executors::ExitKind,
    fuzzer::Evaluator,
    inputs::Input,
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasCurrentStageInfo, HasRand, UsesState},
    Error,
};

// TODO multi mutators stage

/// Action performed after the un-transformed input is executed (e.g., updating metadata)
#[allow(unused_variables)]
pub trait MutatedTransformPost<S>: Sized + Clone {
    /// Perform any post-execution steps necessary for the transformed input (e.g., updating metadata)
    #[inline]
    fn post_exec(
        self,

        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
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
    fn try_transform_from(
        base: &mut Testcase<I>,
        state: &S,
        corpus_idx: CorpusId,
    ) -> Result<Self, Error>;

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
    fn try_transform_from(
        base: &mut Testcase<I>,
        state: &S,
        _corpus_idx: CorpusId,
    ) -> Result<Self, Error> {
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
    Self::State: HasClientPerfMonitor + HasCorpus + HasCurrentStageInfo,
    I: MutatedTransform<Self::Input, Self::State> + Clone,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut Z::State, corpus_idx: CorpusId) -> Result<u64, Error>;
}

/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct StdMutationalStage<E, EM, I, M, MT, Z>
where
    E: UsesState,
    Z: UsesState<State = E::State>,
    MT: MutatedTransformPost<Z::State>,
{
    mutator: M,
    limit: usize,
    corpus_idx: Option<CorpusId>,
    new_corpus_idx: Option<CorpusId>,
    post: Option<MT>,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, Z)>,
}

impl<E, EM, I, M, Z> MutationalStage<E, EM, I, M, Z> for StdMutationalStage<E, EM, I, M, I::Post, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasCurrentStageInfo,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
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
    fn iterations(&self, state: &mut Z::State, _corpus_idx: CorpusId) -> Result<u64, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS))
    }
}

impl<E, EM, I, M, MT, Z> UsesState for StdMutationalStage<E, EM, I, M, MT, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasCurrentStageInfo,
    MT: MutatedTransformPost<Z::State>,
{
    type State = Z::State;
}

impl<E, EM, I, M, Z> Stage<E, EM, Z> for StdMutationalStage<E, EM, I, M, I::Post, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasCurrentStageInfo,
    I: MutatedTransform<Z::Input, Z::State> + Clone,
{
    type Context = I;
    #[inline]
    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<Option<Self::Context>, Error> {
        self.limit = self.iterations(state, corpus_idx)? as usize;
        self.corpus_idx = Some(corpus_idx);

        start_timer!(state);
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let Ok(input) = Self::Context::try_transform_from(&mut testcase, state, corpus_idx) else { return Err(Error::unsupported("Can't transform the input")); };
        drop(testcase);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
        Ok(Some(input))
    }

    #[inline]
    fn limit(&self) -> Result<usize, Error> {
        Ok(self.limit)
    }

    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        mut input: Self::Context,
        index: usize,
    ) -> Result<(Self::Context, bool), Error> {
        start_timer!(state);
        let mutated = self.mutator_mut().mutate(state, &mut input, index as i32)?;
        mark_feature_time!(state, PerfFeature::Mutate);

        if mutated == MutationResult::Skipped {
            Ok((input, false))
        } else {
            Ok((input, true))
        }
    }

    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: Self::Context,
        _index: usize,
    ) -> Result<(Self::Context, ExitKind), Error> {
        // Time is measured directly the `evaluate_input` function
        let (untransformed, post) = input.clone().try_transform_into(state)?;
        let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
        self.post = Some(post);
        self.new_corpus_idx = corpus_idx;
        Ok((input, ExitKind::Ok))
    }

    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: Self::Context,
        index: usize,
        _exit_kind: ExitKind,
    ) -> Result<(Self::Context, Option<usize>), Error> {
        start_timer!(state);
        let new_corpus_idx = self.new_corpus_idx;
        self.mutator_mut()
            .post_exec(state, index as i32, new_corpus_idx)?;
        self.post
            .as_mut()
            .unwrap()
            .clone()
            .post_exec(state, index as i32, new_corpus_idx)?;
        mark_feature_time!(state, PerfFeature::MutatePostExec);
        Ok((input, None))
    }

    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, M, MT, Z> StdMutationalStage<E, EM, Z::Input, M, MT, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<Z::Input, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasCurrentStageInfo,
    MT: MutatedTransformPost<Z::State>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, EM, I, M, MT, Z> StdMutationalStage<E, EM, I, M, MT, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    M: Mutator<I, Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: HasClientPerfMonitor + HasCorpus + HasRand + HasCurrentStageInfo,
    MT: MutatedTransformPost<Z::State>,
{
    /// Creates a new transforming mutational stage
    pub fn transforming(mutator: M) -> Self {
        Self {
            mutator,
            limit: 0,
            corpus_idx: None,
            new_corpus_idx: None,
            post: None,
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
        inputs::BytesInput,
        mutators::pybind::PythonMutator,
        stages::{pybind::PythonStage, StdMutationalStage},
    };

    #[pyclass(unsendable, name = " StdMutationalStage")]
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
