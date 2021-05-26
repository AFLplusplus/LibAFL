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

use crate::{
    bolts::serdeany::SerdeAny,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
};

use alloc::boxed::Box;

/// A `CustomExitKind` for exits that do not fit to one of the default `ExitKind`.
pub trait CustomExitKind: core::fmt::Debug + SerdeAny + 'static {}

/// How an execution finished.
#[derive(Debug)]
pub enum ExitKind {
    /// The run exited normally.
    Ok,
    /// The run resulted in a target crash.
    Crash,
    /// The run hit an out of memory error.
    Oom,
    /// The run timed out
    Timeout,
    /// The run resulted in a custom `ExitKind`.
    Custom(Box<dyn CustomExitKind>),
}

/// Pre and post exec hooks
pub trait HasExecHooks<EM, I, S, Z> {
    /// Called right before exexution starts
    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called right after execution finished.
    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// A haskell-style tuple of objects that have pre and post exec hooks
pub trait HasExecHooksTuple<EM, I, S, Z> {
    /// This is called right before the next execution.
    fn pre_exec_all(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error>;

    /// This is called right after the last execution
    fn post_exec_all(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error>;
}

impl<EM, I, S, Z> HasExecHooksTuple<EM, I, S, Z> for () {
    fn pre_exec_all(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec_all(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, I, S, Z, Head, Tail> HasExecHooksTuple<EM, I, S, Z> for (Head, Tail)
where
    Head: HasExecHooks<EM, I, S, Z>,
    Tail: HasExecHooksTuple<EM, I, S, Z>,
{
    fn pre_exec_all(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.0.pre_exec(fuzzer, state, mgr, input)?;
        self.1.pre_exec_all(fuzzer, state, mgr, input)
    }

    fn post_exec_all(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.0.post_exec(fuzzer, state, mgr, input)?;
        self.1.post_exec_all(fuzzer, state, mgr, input)
    }
}

/// Holds a tuple of Observers
pub trait HasObservers<OT>
where
    OT: ObserversTuple,
{
    /// Get the linked observers
    fn observers(&self) -> &OT;

    /// Get the linked observers
    fn observers_mut(&mut self) -> &mut OT;
}

/// Execute the exec hooks of the observers if they all implement [`HasExecHooks`].
pub trait HasObserversHooks<EM, I, OT, S, Z>: HasObservers<OT>
where
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
    /// Run the pre exec hook for all [`crate::observers::Observer`]`s` linked to this [`Executor`].
    #[inline]
    fn pre_exec_observers(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.observers_mut().pre_exec_all(fuzzer, state, mgr, input)
    }

    /// Run the post exec hook for all the [`crate::observers::Observer`]`s` linked to this [`Executor`].
    #[inline]
    fn post_exec_observers(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.observers_mut()
            .post_exec_all(fuzzer, state, mgr, input)
    }
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
