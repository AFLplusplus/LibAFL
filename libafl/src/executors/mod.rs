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
#[allow(missing_docs)]
/// `Executor` Python bindings
pub mod pybind {
    use crate::events::pybind::PythonEventManager;
    use crate::executors::inprocess::pybind::PythonOwnedInProcessExecutor;
    use crate::executors::{Executor, ExitKind, HasObservers};
    use crate::fuzzer::pybind::{PythonStdFuzzer, PythonStdFuzzerWrapper};
    use crate::inputs::{BytesInput, HasBytesVec};
    use crate::observers::pybind::PythonObserversTuple;
    use crate::state::pybind::{PythonStdState, PythonStdStateWrapper};
    use crate::Error;
    use pyo3::prelude::*;

    #[derive(Clone, Debug)]
    pub struct PyObjectExecutor {
        inner: PyObject,
        tuple: PythonObserversTuple,
    }

    impl PyObjectExecutor {
        pub fn new(obj: PyObject) -> Self {
            let tuple = Python::with_gil(|py| -> PyResult<PythonObserversTuple> {
                obj.call_method1(py, "observers", ())?.extract(py)
            })
            .unwrap();
            PyObjectExecutor { inner: obj, tuple }
        }
    }

    impl HasObservers<BytesInput, PythonObserversTuple, PythonStdState> for PyObjectExecutor {
        #[inline]
        fn observers(&self) -> &PythonObserversTuple {
            &self.tuple
        }

        #[inline]
        fn observers_mut(&mut self) -> &mut PythonObserversTuple {
            &mut self.tuple
        }
    }

    impl Executor<PythonEventManager, BytesInput, PythonStdState, PythonStdFuzzer>
        for PyObjectExecutor
    {
        #[inline]
        fn run_target(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            state: &mut PythonStdState,
            mgr: &mut PythonEventManager,
            input: &BytesInput,
        ) -> Result<ExitKind, Error> {
            // TODO exit kind
            Python::with_gil(|py| -> PyResult<()> {
                self.inner.call_method1(
                    py,
                    "run_target",
                    (
                        PythonStdFuzzerWrapper::wrap(fuzzer),
                        PythonStdStateWrapper::wrap(state),
                        mgr.clone(),
                        input.bytes(),
                    ),
                )?;
                Ok(())
            })
            .unwrap();
            Ok(ExitKind::Ok)
        }
    }

    #[derive(Debug)]
    enum PythonExecutorWrapper {
        InProcess(Py<PythonOwnedInProcessExecutor>),
        Python(PyObjectExecutor),
    }

    #[pyclass(unsendable, name = "Executor")]
    #[derive(Debug)]
    /// Executor + HasObservers Trait binding
    pub struct PythonExecutor {
        wrapper: PythonExecutorWrapper,
    }

    macro_rules! unwrap_me {
        ($wrapper:expr, $name:ident, $body:block) => {
            crate::unwrap_me_body!($wrapper, $name, $body, PythonExecutorWrapper,
                { InProcess },
                {
                    Python(py_wrapper) => {
                        let $name = py_wrapper;
                        $body
                    }
                }
            )
        };
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            crate::unwrap_me_mut_body!($wrapper, $name, $body, PythonExecutorWrapper,
                { InProcess },
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
    impl PythonExecutor {
        #[staticmethod]
        pub fn new_inprocess(owned_inprocess_executor: Py<PythonOwnedInProcessExecutor>) -> Self {
            Self {
                wrapper: PythonExecutorWrapper::InProcess(owned_inprocess_executor),
            }
        }

        #[staticmethod]
        pub fn new_py(obj: PyObject) -> Self {
            Self {
                wrapper: PythonExecutorWrapper::Python(PyObjectExecutor::new(obj)),
            }
        }

        pub fn unwrap_py(&self) -> Option<PyObject> {
            match &self.wrapper {
                PythonExecutorWrapper::Python(pyo) => Some(pyo.inner.clone()),
                _ => None,
            }
        }
    }

    impl HasObservers<BytesInput, PythonObserversTuple, PythonStdState> for PythonExecutor {
        #[inline]
        fn observers(&self) -> &PythonObserversTuple {
            let ptr = unwrap_me!(self.wrapper, e, {
                e.observers() as *const PythonObserversTuple
            });
            unsafe { ptr.as_ref().unwrap() }
        }

        #[inline]
        fn observers_mut(&mut self) -> &mut PythonObserversTuple {
            let ptr = unwrap_me_mut!(self.wrapper, e, {
                e.observers_mut() as *mut PythonObserversTuple
            });
            unsafe { ptr.as_mut().unwrap() }
        }
    }

    impl Executor<PythonEventManager, BytesInput, PythonStdState, PythonStdFuzzer> for PythonExecutor {
        #[inline]
        fn run_target(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            state: &mut PythonStdState,
            mgr: &mut PythonEventManager,
            input: &BytesInput,
        ) -> Result<ExitKind, Error> {
            unwrap_me_mut!(self.wrapper, e, { e.run_target(fuzzer, state, mgr, input) })
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonExecutor>()?;
        Ok(())
    }
}
