//! Executors take input, and run it in the target.

pub mod inprocess;
pub use inprocess::InProcessExecutor;
pub mod timeout;
pub use timeout::TimeoutExecutor;

#[cfg(all(feature = "std", unix))]
pub mod forkserver;
#[cfg(all(feature = "std", unix))]
pub use forkserver::{Forkserver, ForkserverExecutor, OutFile, TimeoutForkserverExecutor};

pub mod combined;
pub use combined::CombinedExecutor;

pub mod shadow;
pub use shadow::ShadowExecutor;

pub mod with_observers;
pub use with_observers::WithObservers;

#[cfg(feature = "std")]
pub mod command;
#[cfg(feature = "std")]
pub use command::CommandExecutor;

use crate::{
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
};

use serde::{Deserialize, Serialize};

/// How an execution finished.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Holds a tuple of Observers
pub trait HasObservers<I, OT, S>
where
    OT: ObserversTuple<I, S>,
{
    /// Get the linked observers
    fn observers(&self) -> &OT;

    /// Get the linked observers
    fn observers_mut(&mut self) -> &mut OT;
}

/// An executor takes the given inputs, and runs the harness/target.
pub trait Executor<EM, I, S, Z>
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
