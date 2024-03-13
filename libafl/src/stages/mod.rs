/*!
A [`Stage`] is a technique used during fuzzing, working on one [`crate::corpus::Corpus`] entry, and potentially altering it or creating new entries.
A well-known [`Stage`], for example, is the mutational stage, running multiple [`crate::mutators::Mutator`]s against a [`crate::corpus::Testcase`], potentially storing new ones, according to [`crate::feedbacks::Feedback`].
Other stages may enrich [`crate::corpus::Testcase`]s with metadata.
*/

use alloc::{boxed::Box, vec::Vec};
use core::{any, marker::PhantomData};

pub use calibrate::CalibrationStage;
pub use colorization::*;
#[cfg(feature = "std")]
pub use concolic::ConcolicTracingStage;
#[cfg(all(feature = "std", feature = "concolic_mutation"))]
pub use concolic::SimpleConcolicMutationalStage;
#[cfg(feature = "std")]
pub use dump::*;
pub use generalization::GeneralizationStage;
use hashbrown::HashSet;
use libafl_bolts::{
    impl_serdeany,
    tuples::{HasConstLen, IntoVec},
    Named,
};
pub use logics::*;
pub use mutational::{MutationalStage, StdMutationalStage};
pub use power::{PowerMutationalStage, StdPowerMutationalStage};
use serde::{Deserialize, Serialize};
pub use stats::AflStatsStage;
#[cfg(feature = "unicode")]
pub use string::*;
#[cfg(feature = "std")]
pub use sync::*;
pub use tmin::{
    MapEqualityFactory, MapEqualityFeedback, StdTMinMutationalStage, TMinMutationalStage,
};
pub use tracing::{ShadowTracingStage, TracingStage};
pub use tuneable::*;
use tuple_list::NonEmptyTuple;

use crate::{
    corpus::{CorpusId, HasCurrentCorpusIdx},
    events::{EventFirer, EventRestarter, HasEventManagerId, ProgressReporter},
    executors::{Executor, HasObservers},
    inputs::UsesInput,
    observers::ObserversTuple,
    schedulers::Scheduler,
    stages::push::PushStage,
    state::{
        HasCorpus, HasExecutions, HasLastReportTime, HasMetadata, HasNamedMetadata, HasRand, State,
        UsesState,
    },
    Error, EvaluatorObservers, ExecutesInput, ExecutionProcessor, HasScheduler,
};

/// Mutational stage is the normal fuzzing stage.
pub mod mutational;
pub mod push;
pub mod tmin;

pub mod calibrate;
pub mod colorization;
#[cfg(feature = "std")]
pub mod concolic;
#[cfg(feature = "std")]
pub mod dump;
pub mod generalization;
pub mod logics;
pub mod power;
pub mod stats;
#[cfg(feature = "unicode")]
pub mod string;
#[cfg(feature = "std")]
pub mod sync;
pub mod tracing;
pub mod tuneable;

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, Z>: UsesState
where
    E: UsesState<State = Self::State>,
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
    /// This method will be called before every call to [`Stage::perform`].
    /// Initialize the restart tracking for this stage, _if it is not yet initialized_.
    /// On restart, this will be called again.
    /// As long as [`Stage::clear_restart_progress`], all subsequent calls happen on restart.
    /// Returns `true`, if the stage's [`Stage::perform`] method should run, else `false`.
    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error>;

    /// Clear the current status tracking of the associated stage
    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error>;

    /// Run the stage.
    ///
    /// Before a call to perform, [`Stage::restart_progress_should_run`] will be (must be!) called.
    /// After returning (so non-target crash or timeout in a restarting case), [`Stage::clear_restart_progress`] gets called.
    /// A call to [`Stage::perform_restartable`] will do these things implicitly.
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error>;

    /// Run the stage, calling [`Stage::restart_progress_should_run`] and [`Stage::clear_restart_progress`] appropriately
    fn perform_restartable(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if self.restart_progress_should_run(state)? {
            self.perform(fuzzer, executor, state, manager)?;
        }
        self.clear_restart_progress(state)
    }
}

/// A tuple holding all `Stages` used for fuzzing.
pub trait StagesTuple<E, EM, S, Z>
where
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
    S: UsesInput + HasCurrentStage,
{
    /// Performs all `Stages` in this tuple
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>;
}

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for ()
where
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
    S: UsesInput + HasCurrentStage,
{
    fn perform_all(
        &mut self,
        _: &mut Z,
        _: &mut E,
        stage: &mut S,
        _: &mut EM,
    ) -> Result<(), Error> {
        if stage.current_stage()?.is_some() {
            Err(Error::illegal_state(
                "Got to the end of the tuple without completing resume.",
            ))
        } else {
            Ok(())
        }
    }
}

impl<Head, Tail, E, EM, Z> StagesTuple<E, EM, Head::State, Z> for (Head, Tail)
where
    Head: Stage<E, EM, Z>,
    Tail: StagesTuple<E, EM, Head::State, Z> + HasConstLen,
    E: UsesState<State = Head::State>,
    EM: UsesState<State = Head::State>,
    Z: UsesState<State = Head::State>,
    Head::State: HasCurrentStage,
{
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Head::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        match state.current_stage()? {
            Some(idx) if idx < Self::LEN => {
                // do nothing; we are resuming
            }
            Some(idx) if idx == Self::LEN => {
                // perform the stage, but don't set it
                let stage = &mut self.0;

                stage.perform_restartable(fuzzer, executor, state, manager)?;

                state.clear_stage()?;
            }
            Some(idx) if idx > Self::LEN => {
                unreachable!("We should clear the stage index before we get here...");
            }
            // this is None, but the match can't deduce that
            _ => {
                state.set_stage(Self::LEN)?;

                let stage = &mut self.0;
                stage.perform_restartable(fuzzer, executor, state, manager)?;

                state.clear_stage()?;
            }
        }

        // Execute the remaining stages
        self.1.perform_all(fuzzer, executor, state, manager)
    }
}

impl<Head, Tail, E, EM, Z>
    IntoVec<Box<dyn Stage<E, EM, Z, State = Head::State, Input = Head::Input>>> for (Head, Tail)
where
    Head: Stage<E, EM, Z> + 'static,
    Tail: StagesTuple<E, EM, Head::State, Z>
        + HasConstLen
        + IntoVec<Box<dyn Stage<E, EM, Z, State = Head::State, Input = Head::Input>>>,
    E: UsesState<State = Head::State>,
    EM: UsesState<State = Head::State>,
    Z: UsesState<State = Head::State>,
    Head::State: HasCurrentStage,
{
    fn into_vec_reversed(
        self,
    ) -> Vec<Box<dyn Stage<E, EM, Z, State = Head::State, Input = Head::Input>>> {
        let (head, tail) = self.uncons();
        let mut ret = tail.0.into_vec_reversed();
        ret.push(Box::new(head));
        ret
    }

    fn into_vec(self) -> Vec<Box<dyn Stage<E, EM, Z, State = Head::State, Input = Head::Input>>> {
        let mut ret = self.into_vec_reversed();
        ret.reverse();
        ret
    }
}

impl<Tail, E, EM, Z> IntoVec<Box<dyn Stage<E, EM, Z, State = Tail::State, Input = Tail::Input>>>
    for (Tail,)
where
    Tail: UsesState + IntoVec<Box<dyn Stage<E, EM, Z, State = Tail::State, Input = Tail::Input>>>,
    Z: UsesState<State = Tail::State>,
    EM: UsesState<State = Tail::State>,
    E: UsesState<State = Tail::State>,
{
    fn into_vec(self) -> Vec<Box<dyn Stage<E, EM, Z, State = Tail::State, Input = Tail::Input>>> {
        self.0.into_vec()
    }
}

impl<E, EM, Z> IntoVec<Box<dyn Stage<E, EM, Z, State = Z::State, Input = Z::Input>>>
    for Vec<Box<dyn Stage<E, EM, Z, State = Z::State, Input = Z::Input>>>
where
    Z: UsesState,
    EM: UsesState<State = Z::State>,
    E: UsesState<State = Z::State>,
{
    fn into_vec(self) -> Vec<Box<dyn Stage<E, EM, Z, State = Z::State, Input = Z::Input>>> {
        self
    }
}

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z>
    for Vec<Box<dyn Stage<E, EM, Z, State = S, Input = S::Input>>>
where
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
    S: UsesInput + HasCurrentStage + State,
{
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        self.iter_mut()
            .try_for_each(|x| x.perform_restartable(fuzzer, executor, state, manager))
    }
}

/// A [`Stage`] that will call a closure
#[derive(Debug)]
pub struct ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<(), Error>,
    E: UsesState,
{
    closure: CB,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, Z> UsesState for ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<(), Error>,
    E: UsesState,
{
    type State = E::State;
}

impl<CB, E, EM, Z> Named for ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<(), Error>,
    E: UsesState,
{
    fn name(&self) -> &str {
        any::type_name::<Self>()
    }
}

impl<CB, E, EM, Z> Stage<E, EM, Z> for ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<(), Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
    E::State: HasNamedMetadata,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        (self.closure)(fuzzer, executor, state, manager)
    }

    #[inline]
    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // Make sure we don't get stuck crashing on a single closure
        RetryRestartHelper::restart_progress_should_run(state, self, 3)
    }

    #[inline]
    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        RetryRestartHelper::clear_restart_progress(state, self)
    }
}

/// A stage that takes a closure
impl<CB, E, EM, Z> ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<(), Error>,
    E: UsesState,
{
    /// Create a new [`ClosureStage`]
    #[must_use]
    pub fn new(closure: CB) -> Self {
        Self {
            closure,
            phantom: PhantomData,
        }
    }
}

impl<CB, E, EM, Z> From<CB> for ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<(), Error>,
    E: UsesState,
{
    #[must_use]
    fn from(closure: CB) -> Self {
        Self::new(closure)
    }
}

/// Allows us to use a [`push::PushStage`] as a normal [`Stage`]
#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct PushStageAdapter<CS, EM, OT, PS, Z> {
    push_stage: PS,
    phantom: PhantomData<(CS, EM, OT, Z)>,
}

impl<CS, EM, OT, PS, Z> PushStageAdapter<CS, EM, OT, PS, Z> {
    /// Create a new [`PushStageAdapter`], wrapping the given [`PushStage`]
    /// to be used as a normal [`Stage`]
    #[must_use]
    pub fn new(push_stage: PS) -> Self {
        Self {
            push_stage,
            phantom: PhantomData,
        }
    }
}

impl<CS, EM, OT, PS, Z> UsesState for PushStageAdapter<CS, EM, OT, PS, Z>
where
    CS: UsesState,
{
    type State = CS::State;
}

impl<CS, E, EM, OT, PS, Z> Stage<E, EM, Z> for PushStageAdapter<CS, EM, OT, PS, Z>
where
    CS: Scheduler,
    CS::State:
        HasExecutions + HasMetadata + HasRand + HasCorpus + HasLastReportTime + HasCurrentCorpusIdx,
    E: Executor<EM, Z> + HasObservers<Observers = OT, State = CS::State>,
    EM: EventFirer<State = CS::State>
        + EventRestarter
        + HasEventManagerId
        + ProgressReporter<State = CS::State>,
    OT: ObserversTuple<CS::State>,
    PS: PushStage<CS, EM, OT, Z>,
    Z: ExecutesInput<E, EM, State = CS::State>
        + ExecutionProcessor<OT, State = CS::State>
        + EvaluatorObservers<OT>
        + HasScheduler<Scheduler = CS>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut CS::State,
        event_mgr: &mut EM,
    ) -> Result<(), Error> {
        let push_stage = &mut self.push_stage;

        let Some(corpus_idx) = state.current_corpus_idx()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };

        push_stage.set_current_corpus_idx(corpus_idx);

        push_stage.init(fuzzer, state, event_mgr, executor.observers_mut())?;

        loop {
            let input =
                match push_stage.pre_exec(fuzzer, state, event_mgr, executor.observers_mut()) {
                    Some(Ok(next_input)) => next_input,
                    Some(Err(err)) => return Err(err),
                    None => break,
                };

            let exit_kind = fuzzer.execute_input(state, executor, event_mgr, &input)?;

            push_stage.post_exec(
                fuzzer,
                state,
                event_mgr,
                executor.observers_mut(),
                input,
                exit_kind,
            )?;
        }

        self.push_stage
            .deinit(fuzzer, state, event_mgr, executor.observers_mut())
    }

    #[inline]
    fn restart_progress_should_run(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // TODO: Proper restart handling - call post_exec at the right time, etc...
        Ok(true)
    }

    #[inline]
    fn clear_restart_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

/// Progress which permits a fixed amount of resumes per round of fuzzing. If this amount is ever
/// exceeded, the input will no longer be executed by this stage.
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct RetryRestartHelper {
    tries_remaining: Option<usize>,
    skipped: HashSet<CorpusId>,
}

impl_serdeany!(RetryRestartHelper);

impl RetryRestartHelper {
    /// Initializes (or counts down in) the progress helper, giving it the amount of max retries
    ///
    /// Returns `true` if the stage should run
    pub fn restart_progress_should_run<S, ST>(
        state: &mut S,
        stage: &ST,
        max_retries: usize,
    ) -> Result<bool, Error>
    where
        S: HasNamedMetadata + HasCurrentCorpusIdx,
        ST: Named,
    {
        let corpus_idx = state.current_corpus_idx()?.ok_or_else(|| {
            Error::illegal_state(
                "No current_corpus_idx set in State, but called RetryRestartHelper::should_skip",
            )
        })?;

        let initial_tries_remaining = max_retries + 1;
        let metadata = state.named_metadata_or_insert_with(stage.name(), || Self {
            tries_remaining: Some(initial_tries_remaining),
            skipped: HashSet::new(),
        });
        let tries_remaining = metadata
            .tries_remaining
            .unwrap_or(initial_tries_remaining)
            .checked_sub(1)
            .ok_or_else(|| {
                Error::illegal_state(
                    "Attempted further retries after we had already gotten to none remaining.",
                )
            })?;

        metadata.tries_remaining = Some(tries_remaining);

        Ok(if tries_remaining == 0 {
            metadata.skipped.insert(corpus_idx);
            false
        } else if metadata.skipped.contains(&corpus_idx) {
            // skip this testcase, we already retried it often enough...
            false
        } else {
            true
        })
    }

    /// Clears the progress
    pub fn clear_restart_progress<S, ST>(state: &mut S, stage: &ST) -> Result<(), Error>
    where
        S: HasNamedMetadata,
        ST: Named,
    {
        state
            .named_metadata_mut::<Self>(stage.name())?
            .tries_remaining = None;
        Ok(())
    }
}

/// Trait for types which track the current stage
pub trait HasCurrentStage {
    /// Set the current stage; we have started processing this stage
    fn set_stage(&mut self, idx: usize) -> Result<(), Error>;

    /// Clear the current stage; we are done processing this stage
    fn clear_stage(&mut self) -> Result<(), Error>;

    /// Fetch the current stage -- typically used after a state recovery or transfer
    fn current_stage(&self) -> Result<Option<usize>, Error>;

    /// Notify of a reset from which we may recover
    fn on_restart(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Trait for types which track nested stages. Stages which themselves contain stage tuples should
/// ensure that they constrain the state with this trait accordingly.
pub trait HasNestedStageStatus: HasCurrentStage {
    /// Enter a stage scope, potentially resuming to an inner stage status. Returns Ok(true) if
    /// resumed.
    fn enter_inner_stage(&mut self) -> Result<(), Error>;

    /// Exit a stage scope
    fn exit_inner_stage(&mut self) -> Result<(), Error>;
}

impl_serdeany!(ExecutionCountRestartHelperMetadata);

/// `SerdeAny` metadata used to keep track of executions since start for a given stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionCountRestartHelperMetadata {
    /// How many executions we had when we started this stage initially (this round)
    started_at_execs: u64,
}

/// A tool shed of functions to be used for stages that try to run for `n` iterations.
///
/// # Note
/// This helper assumes resumable mutational stages are not nested.
/// If you want to nest them, you will have to switch all uses of `metadata` in this helper to `named_metadata` instead.
#[derive(Debug, Default, Clone)]
pub struct ExecutionCountRestartHelper {
    /// At what exec count this Stage was started (cache)
    /// Only used as cache for the value stored in [`MutationalStageMetadata`].
    started_at_execs: Option<u64>,
}

impl ExecutionCountRestartHelper {
    /// Create a new [`ExecutionCountRestartHelperMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at_execs: None,
        }
    }

    /// The execs done since start of this [`Stage`]/helper
    pub fn execs_since_progress_start<S>(&mut self, state: &mut S) -> Result<u64, Error>
    where
        S: HasMetadata + HasExecutions,
    {
        let started_at_execs = if let Some(started_at_execs) = self.started_at_execs {
            started_at_execs
        } else {
            state
                .metadata::<ExecutionCountRestartHelperMetadata>()
                .map(|x| {
                    self.started_at_execs = Some(x.started_at_execs);
                    x.started_at_execs
                })
                .map_err(|err| {
                    Error::illegal_state(format!(
                        "The ExecutionCountRestartHelperMetadata should have been set at this point - {err}"
                    ))
                })?
        };
        Ok(state.executions() - started_at_execs)
    }

    /// Initialize progress for the stage this wrapper wraps.
    pub fn restart_progress_should_run<S>(&mut self, state: &mut S) -> Result<bool, Error>
    where
        S: HasMetadata + HasExecutions,
    {
        let executions = *state.executions();
        let metadata = state.metadata_or_insert_with(|| ExecutionCountRestartHelperMetadata {
            started_at_execs: executions,
        });
        self.started_at_execs = Some(metadata.started_at_execs);
        Ok(true)
    }

    /// Clear progress for the stage this wrapper wraps.
    pub fn clear_restart_progress<S>(&mut self, state: &mut S) -> Result<(), Error>
    where
        S: HasMetadata,
    {
        self.started_at_execs = None;
        let _metadata = state.remove_metadata::<ExecutionCountRestartHelperMetadata>();
        debug_assert!(_metadata.is_some(), "Called clear_restart_progress, but restart_progress_should_run was not called before (or did mutational stages get nested?)");
        Ok(())
    }
}

/// `Stage` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use alloc::vec::Vec;

    use libafl_bolts::Named;
    use pyo3::prelude::*;

    use crate::{
        corpus::HasCurrentCorpusIdx,
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        fuzzer::pybind::{PythonStdFuzzer, PythonStdFuzzerWrapper},
        stages::{
            mutational::pybind::PythonStdMutationalStage, HasCurrentStage, RetryRestartHelper,
            Stage, StagesTuple,
        },
        state::{
            pybind::{PythonStdState, PythonStdStateWrapper},
            UsesState,
        },
        Error,
    };

    #[derive(Clone, Debug)]
    pub struct PyObjectStage {
        inner: PyObject,
    }

    impl PyObjectStage {
        #[must_use]
        pub fn new(obj: PyObject) -> Self {
            PyObjectStage { inner: obj }
        }
    }

    impl UsesState for PyObjectStage {
        type State = PythonStdState;
    }

    impl Named for PyObjectStage {
        fn name(&self) -> &str {
            "PyObjectStage"
        }
    }

    impl Stage<PythonExecutor, PythonEventManager, PythonStdFuzzer> for PyObjectStage {
        #[inline]
        fn perform(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            executor: &mut PythonExecutor,
            state: &mut PythonStdState,
            manager: &mut PythonEventManager,
        ) -> Result<(), Error> {
            let Some(corpus_idx) = state.current_corpus_idx()? else {
                return Err(Error::illegal_state(
                    "state is not currently processing a corpus index",
                ));
            };

            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "perform",
                    (
                        PythonStdFuzzerWrapper::wrap(fuzzer),
                        executor.clone(),
                        PythonStdStateWrapper::wrap(state),
                        manager.clone(),
                        corpus_idx.0,
                    ),
                )?;
                Ok(())
            })?;
            Ok(())
        }

        fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
            // we don't support resumption in python, and maybe can't?
            RetryRestartHelper::restart_progress_should_run(state, self, 2)
        }

        fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
            RetryRestartHelper::clear_restart_progress(state, self)
        }
    }

    #[derive(Clone, Debug)]
    pub enum PythonStageWrapper {
        StdMutational(Py<PythonStdMutationalStage>),
        Python(PyObjectStage),
    }

    /// Stage Trait binding
    #[pyclass(unsendable, name = "Stage")]
    #[derive(Clone, Debug)]
    pub struct PythonStage {
        wrapper: PythonStageWrapper,
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            libafl_bolts::unwrap_me_mut_body!($wrapper, $name, $body, PythonStageWrapper,
                { StdMutational },
                {
                    Python(py_wrapper) => {
                        let $name = py_wrapper;
                        $body
                    }
                }
            )
        };
    }

    #[pymethods]
    impl PythonStage {
        #[staticmethod]
        #[must_use]
        pub fn new_std_mutational(
            py_std_havoc_mutations_stage: Py<PythonStdMutationalStage>,
        ) -> Self {
            Self {
                wrapper: PythonStageWrapper::StdMutational(py_std_havoc_mutations_stage),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_py(obj: PyObject) -> Self {
            Self {
                wrapper: PythonStageWrapper::Python(PyObjectStage::new(obj)),
            }
        }

        #[must_use]
        pub fn unwrap_py(&self) -> Option<PyObject> {
            match &self.wrapper {
                PythonStageWrapper::Python(pyo) => Some(pyo.inner.clone()),
                PythonStageWrapper::StdMutational(_) => None,
            }
        }
    }

    impl UsesState for PythonStage {
        type State = PythonStdState;
    }

    impl Named for PythonStage {
        fn name(&self) -> &str {
            "PythonStage"
        }
    }

    impl Stage<PythonExecutor, PythonEventManager, PythonStdFuzzer> for PythonStage {
        #[inline]
        #[allow(clippy::let_and_return)]
        fn perform(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            executor: &mut PythonExecutor,
            state: &mut PythonStdState,
            manager: &mut PythonEventManager,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, s, {
                s.perform_restartable(fuzzer, executor, state, manager)
            })
        }

        #[inline]
        fn restart_progress_should_run(
            &mut self,
            state: &mut PythonStdState,
        ) -> Result<bool, Error> {
            // TODO we need to apply MutationalStage-like resumption here.
            // For now, make sure we don't get stuck crashing on a single test
            RetryRestartHelper::restart_progress_should_run(state, self, 3)
        }

        #[inline]
        fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
            RetryRestartHelper::clear_restart_progress(state, self)
        }
    }

    #[derive(Clone, Debug)]
    #[pyclass(unsendable, name = "StagesTuple")]
    pub struct PythonStagesTuple {
        list: Vec<PythonStage>,
    }

    #[pymethods]
    impl PythonStagesTuple {
        #[new]
        fn new(list: Vec<PythonStage>) -> Self {
            Self { list }
        }

        fn len(&self) -> usize {
            self.list.len()
        }

        fn __getitem__(&self, idx: usize) -> PythonStage {
            self.list[idx].clone()
        }
    }

    impl StagesTuple<PythonExecutor, PythonEventManager, PythonStdState, PythonStdFuzzer>
        for PythonStagesTuple
    {
        fn perform_all(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            executor: &mut PythonExecutor,
            state: &mut PythonStdState,
            manager: &mut PythonEventManager,
        ) -> Result<(), Error> {
            for (i, s) in self.list.iter_mut().enumerate() {
                if let Some(continued) = state.current_stage()? {
                    assert!(continued >= i);
                    if continued > i {
                        continue;
                    }
                } else {
                    state.set_stage(i)?;
                }
                s.perform_restartable(fuzzer, executor, state, manager)?;
                state.clear_stage()?;
            }
            Ok(())
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStage>()?;
        m.add_class::<PythonStagesTuple>()?;
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use core::marker::PhantomData;

    use libafl_bolts::{impl_serdeany, Error, Named};
    use serde::{Deserialize, Serialize};

    use crate::{
        corpus::{Corpus, HasCurrentCorpusIdx, Testcase},
        inputs::NopInput,
        stages::{RetryRestartHelper, Stage},
        state::{test::test_std_state, HasCorpus, HasMetadata, State, UsesState},
    };

    #[derive(Debug)]
    pub struct ResumeSucceededStage<S> {
        phantom: PhantomData<S>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct TestProgress {
        count: usize,
    }

    impl_serdeany!(TestProgress);

    impl TestProgress {
        #[allow(clippy::unnecessary_wraps)]
        fn restart_progress_should_run<S, ST>(state: &mut S, _stage: &ST) -> Result<bool, Error>
        where
            S: HasMetadata,
        {
            // check if we're resuming
            let metadata = state.metadata_or_insert_with(|| Self { count: 0 });

            metadata.count += 1;
            assert!(
                metadata.count == 1,
                "Test failed; we resumed a succeeded stage!"
            );

            Ok(true)
        }

        fn clear_restart_progress<S, ST>(state: &mut S, _stage: &ST) -> Result<(), Error>
        where
            S: HasMetadata,
        {
            if state.remove_metadata::<Self>().is_none() {
                return Err(Error::illegal_state(
                    "attempted to clear status metadata when none was present",
                ));
            }
            Ok(())
        }
    }

    impl<S> UsesState for ResumeSucceededStage<S>
    where
        S: State,
    {
        type State = S;
    }

    impl<E, EM, Z> Stage<E, EM, Z> for ResumeSucceededStage<Z::State>
    where
        E: UsesState<State = Z::State>,
        EM: UsesState<State = Z::State>,
        Z: UsesState,
        Z::State: HasMetadata,
    {
        fn perform(
            &mut self,
            _fuzzer: &mut Z,
            _executor: &mut E,
            _state: &mut Self::State,
            _manager: &mut EM,
        ) -> Result<(), Error> {
            Ok(())
        }

        fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
            TestProgress::restart_progress_should_run(state, self)
        }

        fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
            TestProgress::clear_restart_progress(state, self)
        }
    }

    #[test]
    fn test_tries_progress() -> Result<(), Error> {
        // # Safety
        // No concurrency per testcase
        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        unsafe {
            RetryRestartHelper::register();
        }

        struct StageWithOneTry;

        impl Named for StageWithOneTry {
            fn name(&self) -> &str {
                "TestStage"
            }
        }

        let mut state = test_std_state();
        let stage = StageWithOneTry;

        let corpus_idx = state.corpus_mut().add(Testcase::new(NopInput {}))?;

        state.set_corpus_idx(corpus_idx)?;

        for _ in 0..10 {
            // used normally, no retries means we never skip
            assert!(RetryRestartHelper::restart_progress_should_run(
                &mut state, &stage, 1
            )?);
            RetryRestartHelper::clear_restart_progress(&mut state, &stage)?;
        }

        for _ in 0..10 {
            // used normally, only one retry means we never skip
            assert!(RetryRestartHelper::restart_progress_should_run(
                &mut state, &stage, 2
            )?);
            assert!(RetryRestartHelper::restart_progress_should_run(
                &mut state, &stage, 2
            )?);
            RetryRestartHelper::clear_restart_progress(&mut state, &stage)?;
        }

        assert!(RetryRestartHelper::restart_progress_should_run(
            &mut state, &stage, 2
        )?);
        // task failed, let's resume
        // we still have one more try!
        assert!(RetryRestartHelper::restart_progress_should_run(
            &mut state, &stage, 2
        )?);

        // task failed, let's resume
        // out of retries, so now we skip
        assert!(!RetryRestartHelper::restart_progress_should_run(
            &mut state, &stage, 2
        )?);
        RetryRestartHelper::clear_restart_progress(&mut state, &stage)?;

        // we previously exhausted this testcase's retries, so we skip
        assert!(!RetryRestartHelper::restart_progress_should_run(
            &mut state, &stage, 2
        )?);
        RetryRestartHelper::clear_restart_progress(&mut state, &stage)?;

        Ok(())
    }
}
