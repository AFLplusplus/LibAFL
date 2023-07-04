/*!
A [`Stage`] is a technique used during fuzzing, working on one [`crate::corpus::Corpus`] entry, and potentially altering it or creating new entries.
A well-known [`Stage`], for example, is the mutational stage, running multiple [`crate::mutators::Mutator`]s against a [`crate::corpus::Testcase`], potentially storing new ones, according to [`crate::feedbacks::Feedback`].
Other stages may enrich [`crate::corpus::Testcase`]s with metadata.
*/

/// Mutational stage is the normal fuzzing stage.
pub mod mutational;
pub use mutational::{MutationalStage, StdMutationalStage};

pub mod tmin;
pub use tmin::{
    MapEqualityFactory, MapEqualityFeedback, StdTMinMutationalStage, TMinMutationalStage,
};

pub mod push;

pub mod tracing;
pub use tracing::{ShadowTracingStage, TracingStage};

pub mod calibrate;
pub use calibrate::CalibrationStage;

pub mod power;
pub use power::{PowerMutationalStage, StdPowerMutationalStage};

pub mod generalization;
pub use generalization::GeneralizationStage;

pub mod owned;
pub use owned::StagesOwnedList;

pub mod logics;
pub use logics::*;

pub mod tuneable;
pub use tuneable::*;

pub mod colorization;
pub use colorization::*;

#[cfg(feature = "std")]
pub mod concolic;
#[cfg(feature = "std")]
pub use concolic::ConcolicTracingStage;
#[cfg(feature = "std")]
pub use concolic::SimpleConcolicMutationalStage;

#[cfg(feature = "std")]
pub mod sync;
#[cfg(feature = "std")]
pub use sync::*;

#[cfg(feature = "std")]
pub mod dump;
use core::{convert::From, ffi::c_void, marker::PhantomData, ptr};

#[cfg(feature = "std")]
pub use dump::*;

use self::push::PushStage;
use crate::executors::ExitKind;
use crate::{
    corpus::CorpusId,
    events::{EventFirer, EventRestarter, HasEventManagerId, ProgressReporter},
    executors::{Executor, HasObservers},
    inputs::UsesInput,
    observers::ObserversTuple,
    schedulers::Scheduler,
    state::{
        HasClientPerfMonitor, HasCorpus, HasCurrentStageInfo, HasExecutions, HasMetadata, HasRand,
        UsesState,
    },
    Error, EvaluatorObservers, ExecutesInput, ExecutionProcessor, HasScheduler,
};

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, Z>: UsesState
where
    Self::State: HasCurrentStageInfo,
    E: UsesState<State = Self::State>,
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
    /// The context passed from one phase of the stage to the next. Typically an Input.
    type Context;

    /// Initialize the stage
    fn init(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<Option<Self::Context>, Error>;

    /// Retrieve the stage's iteration limit. For simple stages this will be 1.
    fn limit(&self) -> Result<usize, Error>;

    /// Executed at the beginning of each iteration, before the target is executed
    fn pre_exec(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: Self::Context,
        index: usize,
    ) -> Result<(Self::Context, bool), Error>;

    /// Run the target
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: Self::Context,
        index: usize,
    ) -> Result<(Self::Context, ExitKind), Error>;
    /// Executed at the end of each iteration, after the target is executed. If the target crashes,
    /// this function will not be executed automatically. It is the responsibility of the crash handler to
    /// call this function to clean up from the iteration.
    fn post_exec(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: Self::Context,
        index: usize,
        exit_kind: ExitKind,
    ) -> Result<(Self::Context, Option<usize>), Error>;

    /// De-initialize the stage
    fn deinit(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error>;

    /// Run the target
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let start = if let Some(current_iteration) = state.current_stage_iteration() {
            current_iteration + 1
        } else {
            0
        };

        let input = self.init(fuzzer, executor, state, manager, corpus_idx)?;
        if let Some(mut input) = input {
            let mut idx = start;
            while idx < self.limit()? {
                state.set_current_stage_iteration(idx);

                let (new_input, run_target) =
                    self.pre_exec(fuzzer, executor, state, manager, input, idx)?;
                input = new_input;

                let (new_input, exit_kind) = if run_target {
                    self.run_target(fuzzer, executor, state, manager, input, idx)?
                } else {
                    (input, ExitKind::Ok)
                };
                input = new_input;

                let (new_input, next_index) =
                    self.post_exec(fuzzer, executor, state, manager, input, idx, exit_kind)?;
                input = new_input;

                if let Some(next_index) = next_index {
                    idx = next_index;
                } else {
                    idx += 1;
                }
            }
        }

        self.deinit(fuzzer, executor, state, manager)?;

        Ok(())
    }
}
static mut CURRENT_STAGE: *mut c_void = ptr::null_mut();

/// Retrieve the current stage from the Global variable
pub unsafe fn current_stage<'a, E, EM, Z>() -> Option<
    alloc::boxed::Box<
        &'a mut dyn Stage<
            E,
            EM,
            Z,
            State = E::State,
            Input = <E::State as UsesInput>::Input,
            Context = <E::State as UsesInput>::Input,
        >,
    >,
>
where
    E: UsesState,
{
    log::error!("postexec  {}", core::any::type_name::<E>());
    log::error!("CURRENT_STAGE @ get: {:?}", CURRENT_STAGE);
    let stage_ptr = CURRENT_STAGE as *mut _
        as *mut &mut dyn Stage<
            E,
            EM,
            Z,
            State = E::State,
            Input = <E::State as UsesInput>::Input,
            Context = <E::State as UsesInput>::Input,
        >;
    if CURRENT_STAGE.is_null() {
        None
    } else {
        Some(alloc::boxed::Box::from_raw(stage_ptr))
    }
}

/// Store the current stage in the Global variable.
pub fn set_current_stage<C, E, EM, Z>(
    stage: &mut dyn Stage<
        E,
        EM,
        Z,
        State = E::State,
        Input = <E::State as UsesInput>::Input,
        Context = C,
    >,
) where
    E: UsesState,
    E::State: HasCurrentStageInfo,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    unsafe { CURRENT_STAGE = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(stage)) as *mut _ };
}

/// A tuple holding all `Stages` used for fuzzing.
pub trait StagesTuple<E, EM, S, Z>
where
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
    S: UsesInput,
{
    /// Performs all `Stages` in this tuple
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error>;
}

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for ()
where
    E: UsesState<State = S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
    S: UsesInput,
{
    fn perform_all(
        &mut self,
        _: &mut Z,
        _: &mut E,
        _: &mut S,
        _: &mut EM,
        _: CorpusId,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, E, EM, Z> StagesTuple<E, EM, Head::State, Z> for (Head, Tail)
where
    Head: Stage<E, EM, Z>,
    Head::State: HasCurrentStageInfo,
    Tail: StagesTuple<E, EM, Head::State, Z>,
    E: UsesState<State = Head::State>,
    EM: UsesState<State = Head::State>,
    Z: UsesState<State = Head::State>,
{
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Head::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        set_current_stage::<Head::Context, E, EM, Z>(&mut self.0);
        if let Some(current_stage_name) = state.current_stage_name() {
            if current_stage_name == core::any::type_name::<Head>() {
                // Perform the current stage
                self.0
                    .perform(fuzzer, executor, state, manager, corpus_idx)?;
                state.clear_current_stage();
            } else {
                // Skip this stage
            }
        } else {
            // We don't have a current stage, so set the current stage name and run the next stage
            state.set_current_stage_name(core::any::type_name::<Head>());
            // Perform the current stage
            self.0
                .perform(fuzzer, executor, state, manager, corpus_idx)?;
            state.clear_current_stage();
        }

        // unsafe { CURRENT_STAGE = ptr::null_mut() };

        // Execute the remaining stages
        self.1
            .perform_all(fuzzer, executor, state, manager, corpus_idx)
    }
}

/// A [`Stage`] that will call a closure
#[derive(Debug)]
pub struct ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<(), Error>,
    E: UsesState,
{
    closure: CB,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, Z> UsesState for ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<(), Error>,
    E: UsesState,
{
    type State = E::State;
}

impl<CB, E, EM, Z> Stage<E, EM, Z> for ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<(), Error>,
    E: UsesState,
    E::State: HasCurrentStageInfo,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    type Context = Self::Input;

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        (self.closure)(fuzzer, executor, state, manager, corpus_idx)
    }

    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<Option<E::Input>, Error> {
        todo!()
    }

    fn limit(&self) -> Result<usize, Error> {
        todo!()
    }

    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, bool), Error> {
        todo!()
    }

    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, ExitKind), Error> {
        todo!()
    }

    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: E::Input,
        _index: usize,
        _exit_kind: ExitKind,
    ) -> Result<(E::Input, Option<usize>), Error> {
        todo!()
    }

    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        todo!()
    }
}

/// A stage that takes a closure
impl<CB, E, EM, Z> ClosureStage<CB, E, EM, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<(), Error>,
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
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<(), Error>,
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
    CS::State: HasClientPerfMonitor
        + HasExecutions
        + HasMetadata
        + HasRand
        + HasCorpus
        + HasCurrentStageInfo,
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
    type Context = Self::Input;

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut CS::State,
        event_mgr: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        let push_stage = &mut self.push_stage;

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

    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
        _corpus_idx: CorpusId,
    ) -> Result<Option<E::Input>, Error> {
        todo!()
    }

    fn limit(&self) -> Result<usize, Error> {
        todo!()
    }

    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, bool), Error> {
        todo!()
    }

    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, ExitKind), Error> {
        todo!()
    }

    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: E::Input,
        _index: usize,
        _exit_kind: ExitKind,
    ) -> Result<(E::Input, Option<usize>), Error> {
        todo!()
    }

    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        todo!()
    }
}

/// `Stage` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use alloc::vec::Vec;

    use pyo3::prelude::*;

    use crate::{
        corpus::CorpusId,
        events::pybind::PythonEventManager,
        executors::pybind::PythonExecutor,
        fuzzer::pybind::{PythonStdFuzzer, PythonStdFuzzerWrapper},
        stages::{mutational::pybind::PythonStdMutationalStage, Stage, StagesTuple},
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

    impl Stage<PythonExecutor, PythonEventManager, PythonInput, PythonStdFuzzer> for PyObjectStage {
        #[inline]
        fn perform(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            executor: &mut PythonExecutor,
            state: &mut PythonStdState,
            manager: &mut PythonEventManager,
            corpus_idx: CorpusId,
        ) -> Result<(), Error> {
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
            crate::unwrap_me_mut_body!($wrapper, $name, $body, PythonStageWrapper,
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
        #[inline]
        #[allow(clippy::let_and_return)]
        fn perform(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            executor: &mut PythonExecutor,
            state: &mut PythonStdState,
            manager: &mut PythonEventManager,
            corpus_idx: CorpusId,
        ) -> Result<(), Error> {
            unwrap_me_mut!(self.wrapper, s, {
                s.perform(fuzzer, executor, state, manager, corpus_idx)
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
            corpus_idx: CorpusId,
        ) -> Result<(), Error> {
            for s in &mut self.list {
                s.perform(fuzzer, executor, state, manager, corpus_idx)?;
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
