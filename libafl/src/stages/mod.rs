/*!
A [`Stage`] is a technique used during fuzzing, working on one [`crate::corpus::Corpus`] entry, and potentially altering it or creating new entries.
A well-known [`Stage`], for example, is the mutational stage, running multiple [`crate::mutators::Mutator`]s against a [`crate::corpus::Testcase`], potentially storing new ones, according to [`crate::feedbacks::Feedback`].
Other stages may enrich [`crate::corpus::Testcase`]s with metadata.
*/

use core::{convert::From, marker::PhantomData};

pub use calibrate::CalibrationStage;
pub use colorization::*;
#[cfg(feature = "std")]
pub use concolic::ConcolicTracingStage;
#[cfg(feature = "std")]
pub use concolic::SimpleConcolicMutationalStage;
#[cfg(feature = "std")]
pub use dump::*;
pub use generalization::GeneralizationStage;
use libafl_bolts::{tuples::HasConstLen, HasLen};
pub use logics::*;
pub use mutational::{MutationalStage, StdMutationalStage};
pub use power::{PowerMutationalStage, StdPowerMutationalStage};
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

use self::push::PushStage;
use crate::{
    corpus::HasCorpusStatus,
    events::{EventFirer, EventRestarter, HasEventManagerId, ProgressReporter},
    executors::{Executor, HasObservers},
    inputs::UsesInput,
    observers::ObserversTuple,
    schedulers::Scheduler,
    state::{HasCorpus, HasExecutions, HasLastReportTime, HasMetadata, HasRand, UsesState},
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
    // TODO: default this to () when associated_type_defaults is stable
    // TODO: see RFC 2532: https://github.com/rust-lang/rust/issues/29661
    // type Status: ResumableStageStatus = ();
    /// The resumption data for this stage. Set to () if resuming is not necessary/possible.
    type Status: ResumableStageStatus<Self::State>;

    /// Run the stage
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error>;
}

/// A tuple holding all `Stages` used for fuzzing.
pub trait StagesTuple<E, EM, S, Z>
where
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
    S: UsesInput + HasStageStatus,
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
    S: UsesInput + HasStageStatus,
{
    fn perform_all(&mut self, _: &mut Z, _: &mut E, _: &mut S, _: &mut EM) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, E, EM, Z> StagesTuple<E, EM, Head::State, Z> for (Head, Tail)
where
    Head: Stage<E, EM, Z>,
    Tail: StagesTuple<E, EM, Head::State, Z> + HasConstLen,
    E: UsesState<State = Head::State>,
    EM: UsesState<State = Head::State>,
    Z: UsesState<State = Head::State>,
    Head::State: HasStageStatus,
{
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Head::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        match state.current_stage()? {
            Some(idx) if idx > Self::LEN => {
                // do nothing; we are resuming
            }
            Some(idx) if idx == Self::LEN => {
                // perform the stage, but don't set it
                self.0.perform(fuzzer, executor, state, manager)?;
                Head::Status::clear_resume_status(state)?;
                state.clear_stage()?;
            }
            Some(idx) if idx < Self::LEN => {
                unreachable!("We should clear the stage index before we get here...");
            }
            // this is None, but the match can't deduce that
            _ => {
                state.set_stage(Self::LEN)?;
                Head::Status::initialize_resume_status(state)?;
                self.0.perform(fuzzer, executor, state, manager)?;
                Head::Status::clear_resume_status(state)?;
                state.clear_stage()?;
            }
        }

        // Execute the remaining stages
        self.1.perform_all(fuzzer, executor, state, manager)
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

impl<CB, E, EM, Z> Stage<E, EM, Z> for ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<(), Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    type Status = ();

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        (self.closure)(fuzzer, executor, state, manager)
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
        HasExecutions + HasMetadata + HasRand + HasCorpus + HasLastReportTime + HasCorpusStatus,
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
    type Status = (); // TODO implement resume

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut CS::State,
        event_mgr: &mut EM,
    ) -> Result<(), Error> {
        let push_stage = &mut self.push_stage;

        push_stage.set_current_corpus_idx(state.current_corpus_idx()?.ok_or_else(|| {
            Error::illegal_state("state is not currently processing a corpus index")
        })?);

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
}

/// `Stage` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use alloc::vec::Vec;

    use pyo3::prelude::*;

    use crate::{
        corpus::HasCorpusStatus,
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        fuzzer::pybind::{PythonStdFuzzer, PythonStdFuzzerWrapper},
        stages::{
            mutational::pybind::PythonStdMutationalStage, HasStageStatus, Stage, StagesTuple,
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

    impl Stage<PythonExecutor, PythonEventManager, PythonStdFuzzer> for PyObjectStage {
        type Status = (); // we don't support resumption in python, and maybe can't?

        #[inline]
        fn perform(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            executor: &mut PythonExecutor,
            state: &mut PythonStdState,
            manager: &mut PythonEventManager,
        ) -> Result<(), Error> {
            let corpus_idx = state.current_corpus_idx()?.ok_or_else(|| {
                Error::illegal_state("state is not currently processing a corpus index")
            })?;

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

    impl Stage<PythonExecutor, PythonEventManager, PythonStdFuzzer> for PythonStage {
        // TODO if we implement resumption for StdMutational, we need to apply it here
        type Status = ();

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
                s.perform(fuzzer, executor, state, manager)
            })
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
                s.perform(fuzzer, executor, state, manager)?;
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

/// Trait for status tracking of stages which stash data to resume
pub trait ResumableStageStatus<S> {
    /// Initialize the current status tracking; stages using this status should "resume" to the
    /// initial step
    fn initialize_resume_status(state: &mut S) -> Result<(), Error>;

    /// Clear the current status tracking of the associated stage
    fn clear_resume_status(state: &mut S) -> Result<(), Error>;

    /// Get the current status tracking of this stage
    fn resume_status(state: &S) -> Result<&Self, Error>;

    /// Get the current status tracking of this stage, mutably
    fn resume_status_mut(state: &mut S) -> Result<&mut Self, Error>;
}

impl<S> ResumableStageStatus<S> for () {
    fn initialize_resume_status(_state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    fn clear_resume_status(_state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    fn resume_status(_state: &S) -> Result<&Self, Error> {
        unimplemented!("The empty tuple resumable stage status should never be queried")
    }

    fn resume_status_mut(_state: &mut S) -> Result<&mut Self, Error> {
        unimplemented!("The empty tuple resumable stage status should never be queried")
    }
}

/// Trait for types which track the current stage
pub trait HasStageStatus {
    /// Set the current stage; we have started processing this stage
    fn set_stage(&mut self, idx: usize) -> Result<(), Error>;

    /// Clear the current stage; we are done processing this stage
    fn clear_stage(&mut self) -> Result<(), Error>;

    /// Fetch the current stage -- typically used after a state recovery or transfer
    fn current_stage(&self) -> Result<Option<usize>, Error>;
}
