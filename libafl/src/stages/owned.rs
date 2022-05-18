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
#[allow(missing_docs)]
/// `StagesOwnedList` Python bindings
pub mod pybind {
    use super::*;
    use crate::stages::owned::StagesOwnedList;
    use crate::stages::pybind::PythonStage;
    use pyo3::prelude::*;

    macro_rules! define_python_stage_owned_list {
        ($struct_name:ident, $py_name:tt, $my_std_state_type_name: ident, $my_std_fuzzer_type_name: ident, $event_manager_name: ident,
            $executor_name: ident) => {
            use crate::events::pybind::$event_manager_name;
            use crate::executors::pybind::$executor_name;
            use crate::fuzzer::pybind::$my_std_fuzzer_type_name;
            use crate::state::pybind::$my_std_state_type_name;

            /// Python class for StagesOwnedList
            #[pyclass(unsendable, name = $py_name)]
            #[allow(missing_debug_implementations)]
            pub struct $struct_name {
                /// Rust wrapped StagesOwnedList object
                pub inner: StagesOwnedList<
                    $executor_name,
                    $event_manager_name,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                >,
            }

            #[pymethods]
            impl $struct_name {
                #[new]
                fn new(stages: Vec<PythonStage>) -> Self {
                    let v: Vec<Box<_>> = stages
                        .into_iter()
                        .map(|x| Box::new(x) as Box<dyn AnyStage<_, _, _, _>>)
                        .collect();
                    Self {
                        inner: StagesOwnedList::new(v),
                    }
                }
            }
        };
    }

    define_python_stage_owned_list!(
        PythonStagesOwnedList,
        "StagesOwnedList",
        PythonStdState,
        PythonStdFuzzer,
        PythonEventManager,
        PythonExecutor
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStagesOwnedList>()?;
        Ok(())
    }
}
