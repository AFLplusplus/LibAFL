pub mod inmemory;

use crate::inputs::Input;
use crate::observers::ObserversTuple;
use crate::AflError;

/// How an execution finished.
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
    fn reset_observers(&mut self) -> Result<(), AflError> {
        self.observers_mut().reset_all()
    }

    /// Run the post exec hook for all the observes linked to this executor
    #[inline]
    fn post_exec_observers(&mut self) -> Result<(), AflError> {
        self.observers_mut().post_exec_all()
    }
}

/// An executor takes the given inputs, and runs the harness/target.
pub trait Executor<I>
where
    I: Input,
{
    /// Instruct the target about the input and run
    fn run_target(&mut self, input: &I) -> Result<ExitKind, AflError>;
}
