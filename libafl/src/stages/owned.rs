//! A dynamic collection of owned Stages

use alloc::{boxed::Box, vec::Vec};

use crate::{
    bolts::anymap::AsAny,
    stages::{Stage, StagesTuple},
    Error,
};

/// Combine `Stage` and `AsAny`
pub trait AnyStage<E, EM, S, Z>: Stage<E, EM, S, Z> + AsAny {}

/// An owned list of `Observer` trait objects
#[derive(Default)]
#[allow(missing_debug_implementations)]
pub struct StagesOwnedList<E, EM, S, Z> {
    /// The named trait objects map
    pub list: Vec<Box<dyn AnyStage<E, EM, S, Z>>>,
}

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for StagesOwnedList<E, EM, S, Z> {
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        for s in &mut self.list {
            s.perform(fuzzer, executor, state, manager, corpus_idx)?;
        }
        Ok(())
    }
}

impl<E, EM, S, Z> StagesOwnedList<E, EM, S, Z> {
    /// Create a new instance
    #[must_use]
    pub fn new(list: Vec<Box<dyn AnyStage<E, EM, S, Z>>>) -> Self {
        Self { list }
    }
}

#[cfg(feature = "python")]
/// `StagesOwnedList` Python bindings
pub mod pybind {
    use crate::stages::owned::StagesOwnedList;
    use pyo3::prelude::*;

    macro_rules! define_python_stage_owned_list {
        ($struct_name:ident, $py_name:tt, $my_std_state_type_name: ident, $my_std_fuzzer_type_name: ident, $event_manager_name: ident,
            $executor_name: ident, $stage_name: ident) => {
            use crate::events::pybind::$event_manager_name;
            use crate::executors::pybind::$executor_name;
            use crate::fuzzer::pybind::$my_std_fuzzer_type_name;
            use crate::stages::pybind::$stage_name;
            use crate::state::pybind::$my_std_state_type_name;
            #[pyclass(unsendable, name = $py_name)]

            /// Python class for StagesOwnedList
            #[allow(missing_debug_implementations)]
            pub struct $struct_name {
                /// Rust wrapped StagesOwnedList object
                pub stages_owned_list: StagesOwnedList<
                    $executor_name,
                    $event_manager_name,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                >,
            }

            #[pymethods]
            impl $struct_name {
                //TODO: Add new from list
                #[new]
                fn new(stage: &$stage_name) -> Self {
                    // TODO: Be safe
                    unsafe {
                        Self {
                            stages_owned_list: StagesOwnedList {
                                list: vec![Box::new(std::mem::transmute_copy::<
                                    $stage_name,
                                    $stage_name,
                                >(stage))],
                            },
                        }
                    }
                }
            }
        };
    }

    define_python_stage_owned_list!(
        PythonStagesOwnedListI8,
        "StagesOwnedListI8",
        MyStdStateI8,
        MyStdFuzzerI8,
        PythonEventManagerI8,
        PythonExecutorI8,
        PythonStageI8
    );

    define_python_stage_owned_list!(
        PythonStagesOwnedListI16,
        "StagesOwnedListI16",
        MyStdStateI16,
        MyStdFuzzerI16,
        PythonEventManagerI16,
        PythonExecutorI16,
        PythonStageI16
    );

    define_python_stage_owned_list!(
        PythonStagesOwnedListI32,
        "StagesOwnedListI32",
        MyStdStateI32,
        MyStdFuzzerI32,
        PythonEventManagerI32,
        PythonExecutorI32,
        PythonStageI32
    );

    define_python_stage_owned_list!(
        PythonStagesOwnedListI64,
        "StagesOwnedListI64",
        MyStdStateI64,
        MyStdFuzzerI64,
        PythonEventManagerI64,
        PythonExecutorI64,
        PythonStageI64
    );

    define_python_stage_owned_list!(
        PythonStagesOwnedListU8,
        "StagesOwnedListU8",
        MyStdStateU8,
        MyStdFuzzerU8,
        PythonEventManagerU8,
        PythonExecutorU8,
        PythonStageU8
    );

    define_python_stage_owned_list!(
        PythonStagesOwnedListU16,
        "StagesOwnedListU16",
        MyStdStateU16,
        MyStdFuzzerU16,
        PythonEventManagerU16,
        PythonExecutorU16,
        PythonStageU16
    );

    define_python_stage_owned_list!(
        PythonStagesOwnedListU32,
        "StagesOwnedListU32",
        MyStdStateU32,
        MyStdFuzzerU32,
        PythonEventManagerU32,
        PythonExecutorU32,
        PythonStageU32
    );

    define_python_stage_owned_list!(
        PythonStagesOwnedListU64,
        "StagesOwnedListU64",
        MyStdStateU64,
        MyStdFuzzerU64,
        PythonEventManagerU64,
        PythonExecutorU64,
        PythonStageU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStagesOwnedListI8>()?;
        m.add_class::<PythonStagesOwnedListI16>()?;
        m.add_class::<PythonStagesOwnedListI32>()?;
        m.add_class::<PythonStagesOwnedListI64>()?;

        m.add_class::<PythonStagesOwnedListU8>()?;
        m.add_class::<PythonStagesOwnedListU16>()?;
        m.add_class::<PythonStagesOwnedListU32>()?;
        m.add_class::<PythonStagesOwnedListU64>()?;
        Ok(())
    }
}
