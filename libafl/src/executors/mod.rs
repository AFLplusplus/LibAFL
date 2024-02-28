//! Executors take input, and run it in the target.

#[cfg(unix)]
use alloc::vec::Vec;
use core::fmt::Debug;

pub use combined::CombinedExecutor;
#[cfg(all(feature = "std", any(unix, doc)))]
pub use command::CommandExecutor;
pub use differential::DiffExecutor;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub use forkserver::{Forkserver, ForkserverExecutor};
pub use inprocess::InProcessExecutor;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub use inprocess_fork::InProcessForkExecutor;
#[cfg(unix)]
use libafl_bolts::os::unix_signals::Signal;
use serde::{Deserialize, Serialize};
pub use shadow::ShadowExecutor;
pub use with_observers::WithObservers;

use crate::{
    observers::{ObserversTuple, UsesObservers},
    state::UsesState,
    Error,
};

pub mod combined;
#[cfg(all(feature = "std", any(unix, doc)))]
pub mod command;
pub mod differential;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub mod forkserver;
pub mod inprocess;

/// The module for inproc fork executor
#[cfg(all(feature = "std", unix))]
pub mod inprocess_fork;

pub mod shadow;

pub mod with_observers;

/// The module for all the hooks
pub mod hooks;

/// How an execution finished.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
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
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
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

libafl_bolts::impl_serdeany!(ExitKind);

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

libafl_bolts::impl_serdeany!(DiffExitKind);

/// Holds a tuple of Observers
pub trait HasObservers: UsesObservers {
    /// Get the linked observers
    fn observers(&self) -> &Self::Observers;

    /// Get the linked observers (mutable)
    fn observers_mut(&mut self) -> &mut Self::Observers;
}

/// An executor takes the given inputs, and runs the harness/target.
pub trait Executor<EM, Z>: UsesState
where
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
    /// Instruct the target about the input and run
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error>;

    /// Wraps this Executor with the given [`ObserversTuple`] to implement [`HasObservers`].
    ///
    /// If the executor already implements [`HasObservers`], then the original implementation will be overshadowed by
    /// the implementation of this wrapper.
    fn with_observers<OT>(self, observers: OT) -> WithObservers<Self, OT>
    where
        Self: Sized,
        OT: ObserversTuple<Self::State>,
    {
        WithObservers::new(self, observers)
    }
}

/// The common signals we want to handle
#[cfg(unix)]
#[inline]
#[must_use]
pub fn common_signals() -> Vec<Signal> {
    vec![
        Signal::SigAlarm,
        Signal::SigUser2,
        Signal::SigAbort,
        Signal::SigBus,
        #[cfg(feature = "handle_sigpipe")]
        Signal::SigPipe,
        Signal::SigFloatingPointException,
        Signal::SigIllegalInstruction,
        Signal::SigSegmentationFault,
        Signal::SigTrap,
    ]
}

#[cfg(test)]
pub mod test {
    use core::marker::PhantomData;

    use libafl_bolts::{AsSlice, Error};

    use crate::{
        events::NopEventManager,
        executors::{Executor, ExitKind},
        fuzzer::test::NopFuzzer,
        inputs::{BytesInput, HasTargetBytes},
        state::{HasExecutions, NopState, State, UsesState},
    };

    /// A simple executor that does nothing.
    /// If intput len is 0, `run_target` will return Err
    #[derive(Debug)]
    pub struct NopExecutor<S> {
        phantom: PhantomData<S>,
    }

    impl<S> NopExecutor<S> {
        #[must_use]
        pub fn new() -> Self {
            Self {
                phantom: PhantomData,
            }
        }
    }

    impl<S> Default for NopExecutor<S> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<S> UsesState for NopExecutor<S>
    where
        S: State,
    {
        type State = S;
    }

    impl<EM, S, Z> Executor<EM, Z> for NopExecutor<S>
    where
        EM: UsesState<State = S>,
        S: State + HasExecutions,
        S::Input: HasTargetBytes,
        Z: UsesState<State = S>,
    {
        fn run_target(
            &mut self,
            _fuzzer: &mut Z,
            state: &mut Self::State,
            _mgr: &mut EM,
            input: &Self::Input,
        ) -> Result<ExitKind, Error> {
            *state.executions_mut() += 1;

            if input.target_bytes().as_slice().is_empty() {
                Err(Error::empty("Input Empty"))
            } else {
                Ok(ExitKind::Ok)
            }
        }
    }

    #[test]
    fn nop_executor() {
        let empty_input = BytesInput::new(vec![]);
        let nonempty_input = BytesInput::new(vec![1u8]);
        let mut executor = NopExecutor::new();
        let mut fuzzer = NopFuzzer::new();

        let mut state = NopState::new();

        executor
            .run_target(
                &mut fuzzer,
                &mut state,
                &mut NopEventManager::new(),
                &empty_input,
            )
            .unwrap_err();
        executor
            .run_target(
                &mut fuzzer,
                &mut state,
                &mut NopEventManager::new(),
                &nonempty_input,
            )
            .unwrap();
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
/// `Executor` Python bindings
pub mod pybind {
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    use crate::{
        events::pybind::PythonEventManager,
        executors::{
            inprocess::pybind::PythonOwnedInProcessExecutor, Executor, ExitKind, HasObservers,
        },
        fuzzer::pybind::{PythonStdFuzzer, PythonStdFuzzerWrapper},
        inputs::HasBytesVec,
        observers::{pybind::PythonObserversTuple, UsesObservers},
        state::{
            pybind::{PythonStdState, PythonStdStateWrapper},
            UsesState,
        },
        Error,
    };

    #[pyclass(unsendable, name = "ExitKind")]
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct PythonExitKind {
        pub inner: ExitKind,
    }

    impl From<ExitKind> for PythonExitKind {
        fn from(inner: ExitKind) -> Self {
            Self { inner }
        }
    }

    #[pymethods]
    impl PythonExitKind {
        fn __eq__(&self, other: &PythonExitKind) -> bool {
            self.inner == other.inner
        }

        #[must_use]
        fn is_ok(&self) -> bool {
            self.inner == ExitKind::Ok
        }

        #[must_use]
        fn is_crash(&self) -> bool {
            self.inner == ExitKind::Crash
        }

        #[must_use]
        fn is_oom(&self) -> bool {
            self.inner == ExitKind::Oom
        }

        #[must_use]
        fn is_timeout(&self) -> bool {
            self.inner == ExitKind::Timeout
        }

        #[staticmethod]
        #[must_use]
        fn ok() -> Self {
            Self {
                inner: ExitKind::Ok,
            }
        }

        #[staticmethod]
        #[must_use]
        fn crash() -> Self {
            Self {
                inner: ExitKind::Crash,
            }
        }

        #[staticmethod]
        #[must_use]
        fn oom() -> Self {
            Self {
                inner: ExitKind::Oom,
            }
        }

        #[staticmethod]
        #[must_use]
        fn timeout() -> Self {
            Self {
                inner: ExitKind::Timeout,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct PyObjectExecutor {
        inner: PyObject,
        tuple: PythonObserversTuple,
    }

    impl PyObjectExecutor {
        #[must_use]
        pub fn new(obj: PyObject) -> Self {
            let tuple = Python::with_gil(|py| -> PyResult<PythonObserversTuple> {
                obj.call_method1(py, "observers", ())?.extract(py)
            })
            .unwrap();
            PyObjectExecutor { inner: obj, tuple }
        }
    }

    impl UsesState for PyObjectExecutor {
        type State = PythonStdState;
    }

    impl UsesObservers for PyObjectExecutor {
        type Observers = PythonObserversTuple;
    }

    impl HasObservers for PyObjectExecutor {
        #[inline]
        fn observers(&self) -> &PythonObserversTuple {
            &self.tuple
        }

        #[inline]
        fn observers_mut(&mut self) -> &mut PythonObserversTuple {
            &mut self.tuple
        }
    }

    impl Executor<PythonEventManager, PythonStdFuzzer> for PyObjectExecutor {
        #[inline]
        fn run_target(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            state: &mut Self::State,
            mgr: &mut PythonEventManager,
            input: &Self::Input,
        ) -> Result<ExitKind, Error> {
            let ek = Python::with_gil(|py| -> PyResult<_> {
                let ek: PythonExitKind = self
                    .inner
                    .call_method1(
                        py,
                        "run_target",
                        (
                            PythonStdFuzzerWrapper::wrap(fuzzer),
                            PythonStdStateWrapper::wrap(state),
                            mgr.clone(),
                            input.bytes(),
                        ),
                    )?
                    .extract(py)?;
                Ok(ek)
            })?;
            Ok(ek.inner)
        }
    }

    #[derive(Clone, Debug)]
    enum PythonExecutorWrapper {
        InProcess(Py<PythonOwnedInProcessExecutor>),
        Python(PyObjectExecutor),
    }

    #[pyclass(unsendable, name = "Executor")]
    #[derive(Clone, Debug)]
    /// Executor<Input = I> + HasObservers Trait binding
    pub struct PythonExecutor {
        wrapper: PythonExecutorWrapper,
    }

    macro_rules! unwrap_me {
        ($wrapper:expr, $name:ident, $body:block) => {
            libafl_bolts::unwrap_me_body!($wrapper, $name, $body, PythonExecutorWrapper,
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
            libafl_bolts::unwrap_me_mut_body!($wrapper, $name, $body, PythonExecutorWrapper,
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
        #[must_use]
        pub fn new_inprocess(owned_inprocess_executor: Py<PythonOwnedInProcessExecutor>) -> Self {
            Self {
                wrapper: PythonExecutorWrapper::InProcess(owned_inprocess_executor),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_py(obj: PyObject) -> Self {
            Self {
                wrapper: PythonExecutorWrapper::Python(PyObjectExecutor::new(obj)),
            }
        }

        #[must_use]
        pub fn unwrap_py(&self) -> Option<PyObject> {
            match &self.wrapper {
                PythonExecutorWrapper::Python(pyo) => Some(pyo.inner.clone()),
                PythonExecutorWrapper::InProcess(_) => None,
            }
        }
    }

    impl UsesState for PythonExecutor {
        type State = PythonStdState;
    }

    impl UsesObservers for PythonExecutor {
        type Observers = PythonObserversTuple;
    }

    impl HasObservers for PythonExecutor {
        #[inline]
        fn observers(&self) -> &PythonObserversTuple {
            let ptr = unwrap_me!(self.wrapper, e, { core::ptr::from_ref(e.observers()) });
            unsafe { ptr.as_ref().unwrap() }
        }

        #[inline]
        fn observers_mut(&mut self) -> &mut PythonObserversTuple {
            let ptr = unwrap_me_mut!(self.wrapper, e, { core::ptr::from_mut(e.observers_mut()) });
            unsafe { ptr.as_mut().unwrap() }
        }
    }

    impl Executor<PythonEventManager, PythonStdFuzzer> for PythonExecutor {
        #[inline]
        fn run_target(
            &mut self,
            fuzzer: &mut PythonStdFuzzer,
            state: &mut Self::State,
            mgr: &mut PythonEventManager,
            input: &Self::Input,
        ) -> Result<ExitKind, Error> {
            unwrap_me_mut!(self.wrapper, e, { e.run_target(fuzzer, state, mgr, input) })
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonExitKind>()?;
        m.add_class::<PythonExecutor>()?;
        Ok(())
    }
}
