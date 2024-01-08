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
use libafl_bolts::tuples::HasConstLen;
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
    corpus::HasCurrentCorpusIdx,
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
    type Progress: StageProgress<Self::State>;

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
                Head::Progress::initialize_progress(state)?;
                self.0.perform(fuzzer, executor, state, manager)?;
                Head::Progress::clear_progress(state)?;
                state.clear_stage()?;
            }
            Some(idx) if idx > Self::LEN => {
                unreachable!("We should clear the stage index before we get here...");
            }
            // this is None, but the match can't deduce that
            _ => {
                state.set_stage(Self::LEN)?;
                Head::Progress::initialize_progress(state)?;
                self.0.perform(fuzzer, executor, state, manager)?;
                Head::Progress::clear_progress(state)?;
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
    type Progress = ();

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
    type Progress = (); // TODO implement resume

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
}

/// `Stage` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use alloc::vec::Vec;

    use pyo3::prelude::*;

    use crate::{
        corpus::HasCurrentCorpusIdx,
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        fuzzer::pybind::{PythonStdFuzzer, PythonStdFuzzerWrapper},
        stages::{
            mutational::pybind::PythonStdMutationalStage, HasCurrentStage, Stage, StagesTuple,
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
        type Progress = (); // we don't support resumption in python, and maybe can't?

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
        type Progress = ();

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
pub trait StageProgress<S> {
    /// Initialize the current status tracking for this stage, if it is not yet initialised
    fn initialize_progress(state: &mut S) -> Result<(), Error>;

    /// Clear the current status tracking of the associated stage
    fn clear_progress(state: &mut S) -> Result<(), Error>;

    /// Get the current status tracking of this stage
    fn progress(state: &S) -> Result<&Self, Error>;

    /// Get the current status tracking of this stage, mutably
    fn progress_mut(state: &mut S) -> Result<&mut Self, Error>;
}

impl<S> StageProgress<S> for () {
    fn initialize_progress(_state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    fn clear_progress(_state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    fn progress(_state: &S) -> Result<&Self, Error> {
        unimplemented!("The empty tuple resumable stage status should never be queried")
    }

    fn progress_mut(_state: &mut S) -> Result<&mut Self, Error> {
        unimplemented!("The empty tuple resumable stage status should never be queried")
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

#[cfg(test)]
pub mod test {
    use alloc::rc::Rc;
    use core::{cell::RefCell, marker::PhantomData};

    use libafl_bolts::{impl_serdeany, Error};
    use serde::{Deserialize, Serialize};
    use tuple_list::{tuple_list, tuple_list_type};

    use crate::{
        events::NopEventManager,
        executors::test::NopExecutor,
        fuzzer::test::NopFuzzer,
        stages::{Stage, StageProgress, StagesTuple},
        state::{HasMetadata, State, UsesState},
    };

    #[derive(Debug)]
    pub struct ResumeSucceededStage<S> {
        phantom: PhantomData<S>,
    }

    #[derive(Debug)]
    pub struct ResumeFailedStage<S> {
        completed: Rc<RefCell<bool>>,
        phantom: PhantomData<S>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct TestProgress {
        count: usize,
    }

    impl_serdeany!(TestProgress);

    impl<S> StageProgress<S> for TestProgress
    where
        S: HasMetadata,
    {
        fn initialize_progress(state: &mut S) -> Result<(), Error> {
            // check if we're resuming
            if !state.has_metadata::<Self>() {
                state.add_metadata(Self { count: 0 });
            }
            Ok(())
        }

        fn clear_progress(state: &mut S) -> Result<(), Error> {
            if state.metadata_map_mut().remove::<Self>().is_none() {
                return Err(Error::illegal_state(
                    "attempted to clear status metadata when none was present",
                ));
            }
            Ok(())
        }

        fn progress(state: &S) -> Result<&Self, Error> {
            state.metadata()
        }

        fn progress_mut(state: &mut S) -> Result<&mut Self, Error> {
            state.metadata_mut()
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
        type Progress = TestProgress;

        fn perform(
            &mut self,
            _fuzzer: &mut Z,
            _executor: &mut E,
            state: &mut Self::State,
            _manager: &mut EM,
        ) -> Result<(), Error> {
            // metadata is attached by the status
            let meta = Self::Progress::progress_mut(state)?;
            meta.count += 1;
            assert!(
                meta.count == 1,
                "Test failed; we resumed a succeeded stage!"
            );

            Ok(())
        }
    }

    impl<S> UsesState for ResumeFailedStage<S>
    where
        S: State,
    {
        type State = S;
    }

    impl<E, EM, Z> Stage<E, EM, Z> for ResumeFailedStage<Z::State>
    where
        E: UsesState<State = Z::State>,
        EM: UsesState<State = Z::State>,
        Z: UsesState,
        Z::State: HasMetadata,
    {
        type Progress = TestProgress;

        fn perform(
            &mut self,
            _fuzzer: &mut Z,
            _executor: &mut E,
            state: &mut Self::State,
            _manager: &mut EM,
        ) -> Result<(), Error> {
            // metadata is attached by the status
            let meta = Self::Progress::progress_mut(state)?;
            meta.count += 1;

            if meta.count == 1 {
                return Err(Error::shutting_down());
            } else if meta.count > 2 {
                panic!("Resume was somehow corrupted?")
            } else {
                self.completed.replace(true);
            }

            Ok(())
        }
    }

    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn test_resume_stages<S>() -> (
        Rc<RefCell<bool>>,
        tuple_list_type!(ResumeSucceededStage<S>, ResumeFailedStage<S>),
    ) {
        let completed = Rc::new(RefCell::new(false));
        (
            completed.clone(),
            tuple_list!(
                ResumeSucceededStage {
                    phantom: PhantomData
                },
                ResumeFailedStage {
                    completed,
                    phantom: PhantomData
                },
            ),
        )
    }

    pub fn test_resume<ST, S>(completed: &Rc<RefCell<bool>>, state: &mut S, mut stages: ST)
    where
        ST: StagesTuple<NopExecutor<S>, NopEventManager<S>, S, NopFuzzer<S>>,
        S: State,
    {
        #[cfg(any(not(feature = "serdeany_autoreg"), miri))]
        unsafe {
            TestProgress::register();
        }

        let mut fuzzer = NopFuzzer::new();
        let mut executor = NopExecutor::new();
        let mut manager = NopEventManager::new();

        for _ in 0..2 {
            completed.replace(false);
            let Err(e) = stages.perform_all(&mut fuzzer, &mut executor, state, &mut manager) else {
                panic!("Test failed; stages should fail the first time.")
            };
            assert!(
                matches!(e, Error::ShuttingDown),
                "Unexpected error encountered."
            );
            assert!(!*completed.borrow(), "Unexpectedly complete?");
            state
                .on_restart()
                .expect("Couldn't notify state of restart.");
            assert!(
                stages
                    .perform_all(&mut fuzzer, &mut executor, state, &mut manager)
                    .is_ok(),
                "Test failed; stages should pass the second time."
            );
            assert!(
                *completed.borrow(),
                "Test failed; we did not set completed."
            );
        }
    }
}
