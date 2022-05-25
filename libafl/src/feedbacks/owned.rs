//! A dynamic collection of owned FeedbackStates

use alloc::{boxed::Box, vec::Vec};

use crate::{
    bolts::anymap::AsAny,
    feedbacks::{FeedbackState, FeedbackStateTuple},
    Error,
};

/// Combine `FeedbackState` and `AsAny`
pub trait AnyFeedbackState: FeedbackState + AsAny {}

/// An owned list of `FeedbackState` trait objects
#[derive(Default)]
#[allow(missing_debug_implementations)]
pub struct FeedbackStatesOwnedList {
    /// The named trait objects map
    pub list: Vec<Box<dyn AnyFeedbackState>>,
}

impl FeedbackStatesTuple for FeedbackStatesOwnedList {
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

impl FeedbackStatesOwnedList {
    /// Create a new instance
    #[must_use]
    pub fn new(list: Vec<Box<dyn AnyFeedbackState>>) -> Self {
        Self { list }
    }
}

#[cfg(feature = "python")]
/// `FeedbackStatesOwnedList` Python bindings
pub mod pybind {
    use crate::stages::owned::FeedbackStatesOwnedList;
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

            /// Python class for FeedbackStatesOwnedList
            #[allow(missing_debug_implementations)]
            pub struct $struct_name {
                /// Rust wrapped FeedbackStatesOwnedList object
                pub stages_owned_list: FeedbackStatesOwnedList<
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
                            stages_owned_list: FeedbackStatesOwnedList {
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
        PythonFeedbackStatesOwnedListI8,
        "FeedbackStatesOwnedListI8",
        MyStdStateI8,
        MyStdFuzzerI8,
        PythonEventManagerI8,
        PythonExecutorI8,
        PythonFeedbackStateI8
    );

    define_python_stage_owned_list!(
        PythonFeedbackStatesOwnedListI16,
        "FeedbackStatesOwnedListI16",
        MyStdStateI16,
        MyStdFuzzerI16,
        PythonEventManagerI16,
        PythonExecutorI16,
        PythonFeedbackStateI16
    );

    define_python_stage_owned_list!(
        PythonFeedbackStatesOwnedListI32,
        "FeedbackStatesOwnedListI32",
        MyStdStateI32,
        MyStdFuzzerI32,
        PythonEventManagerI32,
        PythonExecutorI32,
        PythonFeedbackStateI32
    );

    define_python_stage_owned_list!(
        PythonFeedbackStatesOwnedListI64,
        "FeedbackStatesOwnedListI64",
        MyStdStateI64,
        MyStdFuzzerI64,
        PythonEventManagerI64,
        PythonExecutorI64,
        PythonFeedbackStateI64
    );

    define_python_stage_owned_list!(
        PythonFeedbackStatesOwnedListU8,
        "FeedbackStatesOwnedListU8",
        MyStdStateU8,
        MyStdFuzzerU8,
        PythonEventManagerU8,
        PythonExecutorU8,
        PythonFeedbackStateU8
    );

    define_python_stage_owned_list!(
        PythonFeedbackStatesOwnedListU16,
        "FeedbackStatesOwnedListU16",
        MyStdStateU16,
        MyStdFuzzerU16,
        PythonEventManagerU16,
        PythonExecutorU16,
        PythonFeedbackStateU16
    );

    define_python_stage_owned_list!(
        PythonFeedbackStatesOwnedListU32,
        "FeedbackStatesOwnedListU32",
        MyStdStateU32,
        MyStdFuzzerU32,
        PythonEventManagerU32,
        PythonExecutorU32,
        PythonFeedbackStateU32
    );

    define_python_stage_owned_list!(
        PythonFeedbackStatesOwnedListU64,
        "FeedbackStatesOwnedListU64",
        MyStdStateU64,
        MyStdFuzzerU64,
        PythonEventManagerU64,
        PythonExecutorU64,
        PythonFeedbackStateU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonFeedbackStatesOwnedListI8>()?;
        m.add_class::<PythonFeedbackStatesOwnedListI16>()?;
        m.add_class::<PythonFeedbackStatesOwnedListI32>()?;
        m.add_class::<PythonFeedbackStatesOwnedListI64>()?;

        m.add_class::<PythonFeedbackStatesOwnedListU8>()?;
        m.add_class::<PythonFeedbackStatesOwnedListU16>()?;
        m.add_class::<PythonFeedbackStatesOwnedListU32>()?;
        m.add_class::<PythonFeedbackStatesOwnedListU64>()?;
        Ok(())
    }
}
