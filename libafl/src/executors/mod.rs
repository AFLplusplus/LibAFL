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
            Err(Error::empty("Input Empty"))
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
             $event_manager_name: ident, $in_process_executor_name: ident, $observer_name: ident) => {
            use crate::events::pybind::$event_manager_name;
            use crate::executors::inprocess::pybind::$in_process_executor_name;
            use crate::fuzzer::pybind::$my_std_fuzzer_type_name;
            use crate::observers::pybind::$observer_name;
            use crate::state::pybind::$my_std_state_type_name;

            #[derive(Debug)]
            enum $wrapper_name {
                OwnedInProcess(*mut $in_process_executor_name),
            }

            #[pyclass(unsendable, name = $py_name_trait)]
            #[derive(Debug)]
            /// Executor + HasObservers Trait binding
            pub struct $struct_name_trait {
                wrapper: $wrapper_name,
            }

            impl $struct_name_trait {
                fn unwrap(
                    &self,
                ) -> &(impl Executor<
                    $event_manager_name,
                    BytesInput,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                > + HasObservers<BytesInput, ($observer_name, ()), $my_std_state_type_name>)
                {
                    unsafe {
                        match self.wrapper {
                            $wrapper_name::OwnedInProcess(py_wrapper) => {
                                &(*py_wrapper).upcast()
                            }
                        }
                    }
                }

                fn unwrap_mut(
                    &mut self,
                ) -> &mut (impl Executor<
                    $event_manager_name,
                    BytesInput,
                    $my_std_state_type_name,
                    $my_std_fuzzer_type_name,
                > + HasObservers<
                    BytesInput,
                    ($observer_name, ()),
                    $my_std_state_type_name,
                >) {
                    unsafe {
                        match self.wrapper {
                            $wrapper_name::OwnedInProcess(py_wrapper) => {
                                &mut (*py_wrapper).upcast_mut()
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
                        wrapper: $wrapper_name::OwnedInProcess(owned_inprocess_executor),
                    }
                }
            }

            impl<I, S> HasObservers<I, ($observer_name, ()), S> for $struct_name_trait {
                // #[inline]
                fn observers(&self) -> &($observer_name, ()) {
                    self.unwrap().observers()
                }

                #[inline]
                fn observers_mut(&mut self) -> &mut ($observer_name, ()) {
                    self.unwrap_mut().observers_mut()
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
                    self.unwrap_mut()
                        .run_target(fuzzer, state, mgr, input)
                }
            }
        };
    }

    define_python_executor!(
        PythonExecutor,
        "Executor",
        PythonExecutorWrapper,
        PythonStdState,
        PythonStdFuzzer,
        PythonEventManager,
        PythonOwnedInProcessExecutor,
        PythonObserver
    );

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonExecutor>()?;
        Ok(())
    }
}
