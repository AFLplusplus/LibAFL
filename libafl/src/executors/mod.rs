//! Executors take input, and run it in the target.

pub mod inprocess;
pub use inprocess::InProcessExecutor;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub use inprocess::InProcessForkExecutor;

pub mod differential;
pub use differential::DiffExecutor;

/// Timeout executor.
/// Not possible on `no-std` Windows or `no-std`, but works for unix
#[cfg(any(unix, feature = "std"))]
pub mod timeout;
#[cfg(any(unix, feature = "std"))]
pub use timeout::TimeoutExecutor;

#[cfg(all(feature = "std", feature = "fork", unix))]
pub mod forkserver;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub use forkserver::{Forkserver, ForkserverExecutor, TimeoutForkserverExecutor};

pub mod combined;
pub use combined::CombinedExecutor;

pub mod shadow;
pub use shadow::ShadowExecutor;

pub mod with_observers;
pub use with_observers::WithObservers;

#[cfg(all(feature = "std", unix))]
pub mod command;
#[cfg(all(feature = "std", unix))]
pub use command::CommandExecutor;

use crate::{
    bolts::AsSlice,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
};

use core::fmt::Debug;
use serde::{Deserialize, Serialize};

/// How an execution finished.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExitKind {
    /// The run exited normally.
    Ok,
    /// The run resulted in a target crash.
    Crash,
    /// The run hit an out of memory error.
    Oom,
    /// The run timed out
    Timeout,
    /// Special case for [`DiffExecutor`] when both exitkinds don't match
    Diff {
        /// The exitkind of the primary executor
        primary: DiffExitKind,
        /// The exitkind of the secondary executor
        secondary: DiffExitKind,
    },
    // The run resulted in a custom `ExitKind`.
    // Custom(Box<dyn SerdeAny>),
}

/// How one of the diffing executions finished.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffExitKind {
    /// The run exited normally.
    Ok,
    /// The run resulted in a target crash.
    Crash,
    /// The run hit an out of memory error.
    Oom,
    /// The run timed out
    Timeout,
    /// One of the executors itelf repots a differential, we can't go into further details.
    Diff,
    // The run resulted in a custom `ExitKind`.
    // Custom(Box<dyn SerdeAny>),
}

crate::impl_serdeany!(ExitKind);

impl From<ExitKind> for DiffExitKind {
    fn from(exitkind: ExitKind) -> Self {
        match exitkind {
            ExitKind::Ok => DiffExitKind::Ok,
            ExitKind::Crash => DiffExitKind::Crash,
            ExitKind::Oom => DiffExitKind::Oom,
            ExitKind::Timeout => DiffExitKind::Timeout,
            ExitKind::Diff { .. } => DiffExitKind::Diff,
        }
    }
}

crate::impl_serdeany!(DiffExitKind);

/// Holds a tuple of Observers
pub trait HasObservers<I, OT, S>: Debug
where
    OT: ObserversTuple<I, S>,
{
    /// Get the linked observers
    fn observers(&self) -> &OT;

    /// Get the linked observers (mutable)
    fn observers_mut(&mut self) -> &mut OT;
}

/// An executor takes the given inputs, and runs the harness/target.
pub trait Executor<EM, I, S, Z>: Debug
where
    I: Input,
{
    /// Instruct the target about the input and run
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>;

    /// Wraps this Executor with the given [`ObserversTuple`] to implement [`HasObservers`].
    ///
    /// If the executor already implements [`HasObservers`], then the original implementation will be overshadowed by
    /// the implementation of this wrapper.
    fn with_observers<OT>(self, observers: OT) -> WithObservers<Self, OT>
    where
        Self: Sized,
        OT: ObserversTuple<I, S>,
    {
        WithObservers::new(self, observers)
    }

    /// Custom Reset Handler, e.g., to reset timers
    #[inline]
    fn post_run_reset(&mut self) {}
}

/// A simple executor that does nothing.
/// If intput len is 0, `run_target` will return Err
#[derive(Debug)]
struct NopExecutor {}

impl<EM, I, S, Z> Executor<EM, I, S, Z> for NopExecutor
where
    I: Input + HasTargetBytes,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        if input.target_bytes().as_slice().is_empty() {
            Err(Error::Empty("Input Empty".into()))
        } else {
            Ok(ExitKind::Ok)
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Executor, NopExecutor};
    use crate::inputs::BytesInput;

    #[test]
    fn nop_executor() {
        let empty_input = BytesInput::new(vec![]);
        let nonempty_input = BytesInput::new(vec![1u8]);
        let mut executor = NopExecutor {};
        assert!(executor
            .run_target(&mut (), &mut (), &mut (), &empty_input)
            .is_err());
        assert!(executor
            .run_target(&mut (), &mut (), &mut (), &nonempty_input)
            .is_ok());
    }
}

#[cfg(feature = "python")]
/// `Executor` Python bindings
pub mod pybind {
    use crate::executors::{Executor, ExitKind, HasObservers};
    use crate::inputs::BytesInput;
    use crate::Error;
    use pyo3::prelude::*;

    macro_rules! define_python_executor {
        ($struct_name_trait:ident, $py_name_trait:tt, $wrapper_name: ident, $my_std_state_type_name: ident, $my_std_fuzzer_type_name: ident,
             $event_manager_name: ident, $in_process_executor_name: ident, $map_observer_name: ident) => {
            use crate::events::pybind::$event_manager_name;
            use crate::executors::inprocess::pybind::$in_process_executor_name;
            use crate::fuzzer::pybind::$my_std_fuzzer_type_name;
            use crate::observers::map::pybind::$map_observer_name;
            use crate::state::pybind::$my_std_state_type_name;

            #[derive(Debug)]
            enum $wrapper_name {
                OwnedInProcess(*mut $in_process_executor_name),
            }

            #[pyclass(unsendable, name = $py_name_trait)]
            #[derive(Debug)]
            /// Executor + HasObservers Trait binding
            pub struct $struct_name_trait {
                executor: $wrapper_name,
            }

            impl $struct_name_trait {
                fn get_executor(
                    &self,
                ) -> &(impl Executor<
                    $event_manager_name,
                    BytesInput,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                > + HasObservers<BytesInput, ($map_observer_name, ()), $my_std_state_type_name>)
                {
                    unsafe {
                        match self.executor {
                            $wrapper_name::OwnedInProcess(py_owned_inprocess_executor) => {
                                &(*py_owned_inprocess_executor).owned_in_process_executor
                            }
                        }
                    }
                }

                fn get_mut_executor(
                    &mut self,
                ) -> &mut (impl Executor<
                    $event_manager_name,
                    BytesInput,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                > + HasObservers<
                    BytesInput,
                    ($map_observer_name, ()),
                    $my_std_state_type_name,
                >) {
                    unsafe {
                        match self.executor {
                            $wrapper_name::OwnedInProcess(py_owned_inprocess_executor) => {
                                &mut (*py_owned_inprocess_executor).owned_in_process_executor
                            }
                        }
                    }
                }
            }

            #[pymethods]
            impl $struct_name_trait {
                #[staticmethod]
                fn new_from_inprocess(
                    owned_inprocess_executor: &mut $in_process_executor_name,
                ) -> Self {
                    Self {
                        executor: $wrapper_name::OwnedInProcess(owned_inprocess_executor),
                    }
                }
            }

            impl<I, S> HasObservers<I, ($map_observer_name, ()), S> for $struct_name_trait {
                // #[inline]
                fn observers(&self) -> &($map_observer_name, ()) {
                    self.get_executor().observers()
                }

                #[inline]
                fn observers_mut(&mut self) -> &mut ($map_observer_name, ()) {
                    self.get_mut_executor().observers_mut()
                }
            }

            impl
                Executor<
                    $event_manager_name,
                    BytesInput,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                > for $struct_name_trait
            {
                #[inline]
                fn run_target(
                    &mut self,
                    fuzzer: &mut $my_std_fuzzer_type_name,
                    state: &mut $my_std_state_type_name,
                    mgr: &mut $event_manager_name,
                    input: &BytesInput,
                ) -> Result<ExitKind, Error> {
                    self.get_mut_executor()
                        .run_target(fuzzer, state, mgr, input)
                }
            }
        };
    }

    define_python_executor!(
        PythonExecutorI8,
        "ExecutorI8",
        PythonExecutorWrapperI8,
        MyStdStateI8,
        MyStdFuzzerI8,
        PythonEventManagerI8,
        PythonOwnedInProcessExecutorI8,
        PythonMapObserverI8
    );

    define_python_executor!(
        PythonExecutorI16,
        "ExecutorI16",
        PythonExecutorWrapperI16,
        MyStdStateI16,
        MyStdFuzzerI16,
        PythonEventManagerI16,
        PythonOwnedInProcessExecutorI16,
        PythonMapObserverI16
    );

    define_python_executor!(
        PythonExecutorI32,
        "ExecutorI32",
        PythonExecutorWrapperI32,
        MyStdStateI32,
        MyStdFuzzerI32,
        PythonEventManagerI32,
        PythonOwnedInProcessExecutorI32,
        PythonMapObserverI32
    );

    define_python_executor!(
        PythonExecutorI64,
        "ExecutorI64",
        PythonExecutorWrapperI64,
        MyStdStateI64,
        MyStdFuzzerI64,
        PythonEventManagerI64,
        PythonOwnedInProcessExecutorI64,
        PythonMapObserverI64
    );

    define_python_executor!(
        PythonExecutorU8,
        "ExecutorU8",
        PythonExecutorWrapperU8,
        MyStdStateU8,
        MyStdFuzzerU8,
        PythonEventManagerU8,
        PythonOwnedInProcessExecutorU8,
        PythonMapObserverU8
    );

    define_python_executor!(
        PythonExecutorU16,
        "ExecutorU16",
        PythonExecutorWrapperU16,
        MyStdStateU16,
        MyStdFuzzerU16,
        PythonEventManagerU16,
        PythonOwnedInProcessExecutorU16,
        PythonMapObserverU16
    );

    define_python_executor!(
        PythonExecutorU32,
        "ExecutorU32",
        PythonExecutorWrapperU32,
        MyStdStateU32,
        MyStdFuzzerU32,
        PythonEventManagerU32,
        PythonOwnedInProcessExecutorU32,
        PythonMapObserverU32
    );

    define_python_executor!(
        PythonExecutorU64,
        "ExecutorU64",
        PythonExecutorWrapperU64,
        MyStdStateU64,
        MyStdFuzzerU64,
        PythonEventManagerU64,
        PythonOwnedInProcessExecutorU64,
        PythonMapObserverU64
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonExecutorI8>()?;
        m.add_class::<PythonExecutorI16>()?;
        m.add_class::<PythonExecutorI32>()?;
        m.add_class::<PythonExecutorI64>()?;

        m.add_class::<PythonExecutorU8>()?;
        m.add_class::<PythonExecutorU16>()?;
        m.add_class::<PythonExecutorU32>()?;
        m.add_class::<PythonExecutorU64>()?;
        Ok(())
    }
}
