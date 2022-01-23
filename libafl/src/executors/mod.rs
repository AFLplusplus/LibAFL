//! Executors take input, and run it in the target.

pub mod inprocess;
pub use inprocess::InProcessExecutor;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub use inprocess::InProcessForkExecutor;

/// Timeout executor.
/// Not possible on `no-std` Windows or `no-std`, but works for unix
#[cfg(any(unix, feature = "std"))]
pub mod timeout;
#[cfg(any(unix, feature = "std"))]
pub use timeout::TimeoutExecutor;

#[cfg(all(feature = "std", feature = "fork", unix))]
pub mod forkserver;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub use forkserver::{Forkserver, ForkserverExecutor, OutFile, TimeoutForkserverExecutor};

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
    // The run resulted in a custom `ExitKind`.
    // Custom(Box<dyn SerdeAny>),
}

crate::impl_serdeany!(ExitKind);

/// Holds a tuple of Observers
pub trait HasObservers<I, OT, S>: Debug
where
    OT: ObserversTuple<I, S>,
{
    /// Get the linked observers
    fn observers(&self) -> &OT;

    /// Get the linked observers
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
/// Executor Python bindings
pub mod pybind {
    use crate::events::pybind::PythonEventManager;
    use crate::executors::{
        inprocess::pybind::PythonOwnedInProcessExecutorI32, Executor, ExitKind, HasObservers,
    };
    use crate::fuzzer::pybind::MyStdFuzzer;
    use crate::inputs::BytesInput;
    use crate::observers::map::pybind::PythonMapObserverI32;
    use crate::state::pybind::MyStdState;
    use crate::Error;
    use pyo3::prelude::*;

    #[derive(Debug)]
    enum PythonExecutorWrapperI32 {
        OwnedInProcess(*mut PythonOwnedInProcessExecutorI32),
    }

    
    #[pyclass(unsendable, name = "ExecutorI32")]
    #[derive(Debug)]
    /// Executor + HasObservers Trait binding
    pub struct PythonExecutorI32 {
        executor: PythonExecutorWrapperI32,
    }

    impl PythonExecutorI32 {
        fn get_executor(
            &self,
        ) -> &(impl Executor<PythonEventManager, BytesInput, MyStdState, MyStdFuzzer>
                 + HasObservers<BytesInput, (PythonMapObserverI32, ()), MyStdState>) {
            unsafe {
                match self.executor {
                    PythonExecutorWrapperI32::OwnedInProcess(py_owned_inprocess_executor) => {
                        &(*py_owned_inprocess_executor).owned_in_process_executor
                    }
                }
            }
        }

        fn get_mut_executor(
            &self,
        ) -> &mut (impl Executor<PythonEventManager, BytesInput, MyStdState, MyStdFuzzer>
                     + HasObservers<BytesInput, (PythonMapObserverI32, ()), MyStdState>) {
            unsafe {
                match self.executor {
                    PythonExecutorWrapperI32::OwnedInProcess(py_owned_inprocess_executor) => {
                        &mut (*py_owned_inprocess_executor).owned_in_process_executor
                    }
                }
            }
        }
    }

    #[pymethods]
    impl PythonExecutorI32 {
        #[staticmethod]
        fn new_from_inprocess(
            owned_inprocess_executor: &mut PythonOwnedInProcessExecutorI32,
        ) -> Self {
            Self {
                executor: PythonExecutorWrapperI32::OwnedInProcess(owned_inprocess_executor),
            }
        }
    }

    impl<I, S> HasObservers<I, (PythonMapObserverI32, ()), S> for PythonExecutorI32 {
        // #[inline]
        fn observers(&self) -> &(PythonMapObserverI32, ()) {
            self.get_executor().observers()
        }

        #[inline]
        fn observers_mut(&mut self) -> &mut (PythonMapObserverI32, ()) {
            self.get_mut_executor().observers_mut()
        }
    }

    impl Executor<PythonEventManager, BytesInput, MyStdState, MyStdFuzzer> for PythonExecutorI32 {
        #[inline]
        fn run_target(
            &mut self,
            fuzzer: &mut MyStdFuzzer,
            state: &mut MyStdState,
            mgr: &mut PythonEventManager,
            input: &BytesInput,
        ) -> Result<ExitKind, Error> {
            self.get_mut_executor()
                .run_target(fuzzer, state, mgr, input)
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonExecutorI32>()?;
        Ok(())
    }
}
