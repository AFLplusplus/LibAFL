pub mod inmemory;

use alloc::boxed::Box;

use crate::inputs::Input;
use crate::observers::observer_serde::NamedSerdeAnyMap;
use crate::observers::Observer;
use crate::AflError;

/// How an execution finished.
pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout,
}

/// An executor takes the given inputs, and runs the harness/target.
pub trait Executor<I>
where
    I: Input,
{
    /// Instruct the target about the input and run
    fn run_target(&mut self, input: &I) -> Result<ExitKind, AflError>;

    /// Get the linked observers
    fn observers(&self) -> &NamedSerdeAnyMap;

    /// Get the linked observers
    fn observers_mut(&mut self) -> &mut NamedSerdeAnyMap;

    /// Add a linked observer
    fn add_observer(&mut self, observer: Box<dyn Observer>) {
        let name = observer.name().clone();
        self.observers_mut().insert(observer, &name);
    }

    /// Reset the state of all the observes linked to this executor
    fn reset_observers(&mut self) -> Result<(), AflError> {
        self.observers_mut().for_each_mut(|_, x| Ok(x.reset()?))?;
        Ok(())
    }

    /// Run the post exec hook for all the observes linked to this executor
    fn post_exec_observers(&mut self) -> Result<(), AflError> {
        self.observers_mut()
            .for_each_mut(|_, x| Ok(x.post_exec()?))?;
        Ok(())
    }
}
