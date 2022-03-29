/*!
A [`Stage`] is a technique used during fuzzing, working on one [`crate::corpus::Corpus`] entry, and potentially altering it or creating new entries.
A well-known [`Stage`], for example, is the mutational stage, running multiple [`crate::mutators::Mutator`]s against a [`crate::corpus::Testcase`], potentially storing new ones, according to [`crate::feedbacks::Feedback`].
Other stages may enrich [`crate::corpus::Testcase`]s with metadata.
*/

/// Mutational stage is the normal fuzzing stage.
pub mod mutational;
pub use mutational::{MutationalStage, StdMutationalStage};

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

use crate::{
    events::{EventFirer, EventRestarter, HasEventManagerId, ProgressReporter},
    executors::{Executor, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    schedulers::Scheduler,
    state::{
        HasExecutions, HasRand, {HasClientPerfMonitor, HasCorpus},
    },
    Error, EvaluatorObservers, ExecutesInput, ExecutionProcessor, HasScheduler,
};
use core::{convert::From, marker::PhantomData};

use self::push::PushStage;

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, S, Z> {
    /// Run the stage
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

/// A tuple holding all `Stages` used for fuzzing.
pub trait StagesTuple<E, EM, S, Z> {
    /// Performs all `Stages` in this tuple
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for () {
    fn perform_all(
        &mut self,
        _: &mut Z,
        _: &mut E,
        _: &mut S,
        _: &mut EM,
        _: usize,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, E, EM, S, Z> StagesTuple<E, EM, S, Z> for (Head, Tail)
where
    Head: Stage<E, EM, S, Z>,
    Tail: StagesTuple<E, EM, S, Z>,
{
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        // Perform the current stage
        self.0
            .perform(fuzzer, executor, state, manager, corpus_idx)?;

        // Execute the remaining stages
        self.1
            .perform_all(fuzzer, executor, state, manager, corpus_idx)
    }
}

/// A [`Stage`] that will call a closure
#[derive(Debug)]
pub struct ClosureStage<CB, E, EM, S, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM, usize) -> Result<(), Error>,
{
    closure: CB,
    phantom: PhantomData<(E, EM, S, Z)>,
}

impl<CB, E, EM, S, Z> Stage<E, EM, S, Z> for ClosureStage<CB, E, EM, S, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM, usize) -> Result<(), Error>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        (self.closure)(fuzzer, executor, state, manager, corpus_idx)
    }
}

/// A stage that takes a closure
impl<CB, E, EM, S, Z> ClosureStage<CB, E, EM, S, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM, usize) -> Result<(), Error>,
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

impl<CB, E, EM, S, Z> From<CB> for ClosureStage<CB, E, EM, S, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM, usize) -> Result<(), Error>,
{
    #[must_use]
    fn from(closure: CB) -> Self {
        Self::new(closure)
    }
}

/// Allows us to use a [`push::PushStage`] as a normal [`Stage`]
#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct PushStageAdapter<CS, EM, I, OT, PS, S, Z>
where
    CS: Scheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId + ProgressReporter<I>,
    I: Input,
    OT: ObserversTuple<I, S>,
    PS: PushStage<CS, EM, I, OT, S, Z>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasExecutions,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasScheduler<CS, I, S>,
{
    push_stage: PS,
    phantom: PhantomData<(CS, EM, I, OT, S, Z)>,
}

impl<CS, EM, I, OT, PS, S, Z> PushStageAdapter<CS, EM, I, OT, PS, S, Z>
where
    CS: Scheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId + ProgressReporter<I>,
    I: Input,
    OT: ObserversTuple<I, S>,
    PS: PushStage<CS, EM, I, OT, S, Z>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasExecutions,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasScheduler<CS, I, S>,
{
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

impl<CS, E, EM, I, OT, PS, S, Z> Stage<E, EM, S, Z> for PushStageAdapter<CS, EM, I, OT, PS, S, Z>
where
    CS: Scheduler<I, S>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId + ProgressReporter<I>,
    I: Input,
    OT: ObserversTuple<I, S>,
    PS: PushStage<CS, EM, I, OT, S, Z>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasRand + HasExecutions,
    Z: ExecutesInput<I, OT, S, Z>
        + ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + HasScheduler<CS, I, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        event_mgr: &mut EM,
        corpus_idx: usize,
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
}

/// `Stage` Python bindings
#[cfg(feature = "python")]
pub mod pybind {
    use crate::impl_asany;
    use crate::stages::Stage;
    use crate::Error;
    use pyo3::prelude::*;

    use super::owned::AnyStage;

    macro_rules! define_python_stage {
        ($struct_name_trait:ident, $py_name_trait:tt, $wrapper_name: ident, $std_havoc_mutations_stage_name: ident, $my_std_state_type_name: ident,
            $my_std_fuzzer_type_name: ident, $executor_name: ident, $event_manager_name: ident) => {
            use crate::events::pybind::$event_manager_name;
            use crate::executors::pybind::$executor_name;
            use crate::fuzzer::pybind::$my_std_fuzzer_type_name;
            use crate::stages::mutational::pybind::$std_havoc_mutations_stage_name;
            use crate::state::pybind::$my_std_state_type_name;

            #[derive(Debug)]
            enum $wrapper_name {
                StdHavocMutations(*mut $std_havoc_mutations_stage_name),
            }

            /// Stage Trait binding
            #[pyclass(unsendable, name = $py_name_trait)]
            #[derive(Debug)]
            pub struct $struct_name_trait {
                stage: $wrapper_name,
            }

            #[pymethods]
            impl $struct_name_trait {
                #[staticmethod]
                fn new_from_std_scheduled(
                    py_std_havoc_mutations_stage: &mut $std_havoc_mutations_stage_name,
                ) -> Self {
                    Self {
                        stage: $wrapper_name::StdHavocMutations(py_std_havoc_mutations_stage),
                    }
                }
            }

            impl
                Stage<
                    $executor_name,
                    $event_manager_name,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                > for $struct_name_trait
            {
                #[inline]
                #[allow(clippy::let_and_return)]
                fn perform(
                    &mut self,
                    fuzzer: &mut $my_std_fuzzer_type_name,
                    executor: &mut $executor_name,
                    state: &mut $my_std_state_type_name,
                    manager: &mut $event_manager_name,
                    corpus_idx: usize,
                ) -> Result<(), Error> {
                    unsafe {
                        match self.stage {
                            $wrapper_name::StdHavocMutations(py_std_havoc_mutations_stage) => {
                                (*py_std_havoc_mutations_stage)
                                    .std_mutational_stage
                                    .perform(fuzzer, executor, state, manager, corpus_idx)
                            }
                        }
                    }
                }
            }

            impl_asany!($struct_name_trait);

            impl
                AnyStage<
                    $executor_name,
                    $event_manager_name,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                > for $struct_name_trait
            {
            }
        };
    }

    define_python_stage!(
        PythonStageI8,
        "StageI8",
        PythonStageWrapperI8,
        PythonStdScheduledHavocMutationsStageI8,
        MyStdStateI8,
        MyStdFuzzerI8,
        PythonExecutorI8,
        PythonEventManagerI8
    );

    define_python_stage!(
        PythonStageI16,
        "StageI16",
        PythonStageWrapperI16,
        PythonStdScheduledHavocMutationsStageI16,
        MyStdStateI16,
        MyStdFuzzerI16,
        PythonExecutorI16,
        PythonEventManagerI16
    );

    define_python_stage!(
        PythonStageI32,
        "StageI32",
        PythonStageWrapperI32,
        PythonStdScheduledHavocMutationsStageI32,
        MyStdStateI32,
        MyStdFuzzerI32,
        PythonExecutorI32,
        PythonEventManagerI32
    );

    define_python_stage!(
        PythonStageI64,
        "StageI64",
        PythonStageWrapperI64,
        PythonStdScheduledHavocMutationsStageI64,
        MyStdStateI64,
        MyStdFuzzerI64,
        PythonExecutorI64,
        PythonEventManagerI64
    );

    define_python_stage!(
        PythonStageU8,
        "StageU8",
        PythonStageWrapperU8,
        PythonStdScheduledHavocMutationsStageU8,
        MyStdStateU8,
        MyStdFuzzerU8,
        PythonExecutorU8,
        PythonEventManagerU8
    );
    define_python_stage!(
        PythonStageU16,
        "StageU16",
        PythonStageWrapperU16,
        PythonStdScheduledHavocMutationsStageU16,
        MyStdStateU16,
        MyStdFuzzerU16,
        PythonExecutorU16,
        PythonEventManagerU16
    );
    define_python_stage!(
        PythonStageU32,
        "StageU32",
        PythonStageWrapperU32,
        PythonStdScheduledHavocMutationsStageU32,
        MyStdStateU32,
        MyStdFuzzerU32,
        PythonExecutorU32,
        PythonEventManagerU32
    );
    define_python_stage!(
        PythonStageU64,
        "StageU64",
        PythonStageWrapperU64,
        PythonStdScheduledHavocMutationsStageU64,
        MyStdStateU64,
        MyStdFuzzerU64,
        PythonExecutorU64,
        PythonEventManagerU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStageI8>()?;
        m.add_class::<PythonStageI16>()?;
        m.add_class::<PythonStageI32>()?;
        m.add_class::<PythonStageI64>()?;

        m.add_class::<PythonStageU8>()?;
        m.add_class::<PythonStageU16>()?;
        m.add_class::<PythonStageU32>()?;
        m.add_class::<PythonStageU64>()?;
        Ok(())
    }
}
