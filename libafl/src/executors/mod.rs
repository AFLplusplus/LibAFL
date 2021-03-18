//! Executors take input, and run it in the target.

pub mod inprocess;
pub use inprocess::InProcessExecutor;
pub mod timeout;
pub use timeout::TimeoutExecutor;
#[cfg(feature = "runtime")]
pub mod runtime;

use core::cmp::PartialEq;
use core::marker::PhantomData;

use crate::{
    bolts::tuples::Named,
    events::EventManager,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    Error,
};

/// How an execution finished.
#[derive(Debug, Clone, PartialEq)]
pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout,
}

pub trait HasObservers<OT>
where
    OT: ObserversTuple,
{
    /// Get the linked observers
    fn observers(&self) -> &OT;

    /// Get the linked observers
    fn observers_mut(&mut self) -> &mut OT;

    /// Reset the state of all the observes linked to this executor
    #[inline]
    fn pre_exec_observers(&mut self) -> Result<(), Error> {
        self.observers_mut().pre_exec_all()
    }

    /// Run the post exec hook for all the observes linked to this executor
    #[inline]
    fn post_exec_observers(&mut self) -> Result<(), Error> {
        self.observers_mut().post_exec_all()
    }
}

/// A simple executor that does nothing.
/// If intput len is 0, run_target will return Err
struct NopExecutor<I> {
    phantom: PhantomData<I>,
}

impl<I> Executor<I> for NopExecutor<I>
where
    I: Input + HasTargetBytes,
{
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        if input.target_bytes().as_slice().is_empty() {
            Err(Error::Empty("Input Empty".into()))
        } else {
            Ok(ExitKind::Ok)
        }
    }
}

impl<I> Named for NopExecutor<I> {
    fn name(&self) -> &str {
        &"NopExecutor"
    }
}

/// An executor takes the given inputs, and runs the harness/target.
pub trait Executor<I>: Named
where
    I: Input,
{
    /// Called right before exexution starts
    #[inline]
    fn pre_exec<EM, S>(
        &mut self,
        _state: &mut S,
        _event_mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        Ok(())
    }

    /// Called right after execution finished.
    #[inline]
    fn post_exec<EM, S>(&mut self, _state: &mut S, _event_mgr: &mut EM, _input: &I) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        Ok(())
    }

    /// Instruct the target about the input and run
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error>;
}

#[cfg(test)]
mod test {
    use core::marker::PhantomData;

    use super::{Executor, NopExecutor};
    use crate::inputs::BytesInput;

    #[test]
    fn nop_executor() {
        let empty_input = BytesInput::new(vec![]);
        let nonempty_input = BytesInput::new(vec![1u8]);
        let mut executor = NopExecutor {
            phantom: PhantomData,
        };
        assert!(executor.run_target(&empty_input).is_err());
        assert!(executor.run_target(&nonempty_input).is_ok());
    }
}
