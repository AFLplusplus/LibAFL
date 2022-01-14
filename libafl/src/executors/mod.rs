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
pub mod pybind {
    use std::rc::Rc;

    use crate::bolts::{rands::StdRand, tuples::tuple_list};
    use crate::corpus::{InMemoryCorpus, OnDiskCorpus};
    use crate::events::simple::pybind::PythonSimpleEventManager;
    use crate::events::SimpleEventManager;
    use crate::executors::HasObservers;
    use crate::executors::{
        inprocess::{pybind::PythonOwnedInProcessExecutorI32, OwnedInProcessExecutor},
        Executor,
    };
    use crate::feedbacks::MapFeedbackState;
    use crate::fuzzer::pybind::{MyStdFuzzer, PythonStdFuzzerI32};
    use crate::inputs::{BytesInput, HasBytesVec, HasTargetBytes, Input};
    use crate::monitors::SimpleMonitor;
    use crate::observers::{map::pybind::PythonMapObserverI32, ObserversTuple};
    use crate::state::{
        pybind::{MyStdState, PythonStdState},
        StdState,
    };

    use pyo3::prelude::*;

    #[derive(Debug)]
    pub enum PythonExecutorWrapperI32 {
        OwnedInProcess(*mut PythonOwnedInProcessExecutorI32),
    }

    // Not Exposed to user
    #[pyclass(unsendable, name = "ExecutorI32")]
    #[derive(Debug)]
    pub struct PythonExecutorI32 {
        pub executor: PythonExecutorWrapperI32,
    }

    impl PythonExecutorI32 {
        pub fn get_executor(
            &self,
        ) -> &(impl Executor<
            SimpleEventManager<BytesInput, SimpleMonitor<fn(String)>>,
            BytesInput,
            MyStdState,
            MyStdFuzzer,
        > + HasObservers<BytesInput, (), MyStdState>)
        {
            unsafe {
                match &self.executor {
                    PythonExecutorWrapperI32::OwnedInProcess(owned_inprocess_executor) => {
                        &(*(*owned_inprocess_executor)).owned_in_process_executor
                    }
                    _ => panic!("Executor not supported"),
                }
            }
        }

        pub fn get_mut_executor(
            &self,
        ) -> &mut (impl Executor<
            SimpleEventManager<BytesInput, SimpleMonitor<fn(String)>>,
            BytesInput,
            MyStdState,
            MyStdFuzzer,
        > + HasObservers<BytesInput, (PythonMapObserverI32, ()), MyStdState>) {
            unsafe {
                match &self.executor {
                    PythonExecutorWrapperI32::OwnedInProcess(owned_inprocess_executor) => {
                        &mut (*(*owned_inprocess_executor)).owned_in_process_executor
                    }
                    _ => panic!("Executor not supported"),
                }
            }
        }
    }

    #[pymethods]
    impl PythonExecutorI32 {
        #[staticmethod]
        fn new(owned_inprocess_executor: &mut PythonOwnedInProcessExecutorI32) -> Self {
            Self {
                executor: PythonExecutorWrapperI32::OwnedInProcess(owned_inprocess_executor),
            }
        }
    }

    impl<I, OT, S> HasObservers<I, OT, S> for PythonExecutorI32
    where
        I: Input,
        OT: ObserversTuple<I, S>,
    {
        #[inline]
        fn observers(&self) -> &OT {
            self.get_executor().observers()
        }

        #[inline]
        fn observers_mut(&mut self) -> &mut OT {
            self.get_mut_executor().observers_mut()
        }
    }

    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonExecutorI32>()?;
        Ok(())
    }
}
