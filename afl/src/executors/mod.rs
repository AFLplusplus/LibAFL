pub mod inmemory;

use crate::inputs::Input;
use crate::observers::Observer;
use crate::metamap::NamedAnyMap;
use crate::AflError;

pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout,
}

// TODO unbox input

pub trait Executor<I>
where
    I: Input,
{
    /// Instruct the target about the input and run
    fn run_target(&mut self, input: &I) -> Result<ExitKind, AflError>;

    /// Get the linked observers
    fn observers(&self) -> &NamedAnyMap;

    /// Get the linked observers
    fn observers_mut(&mut self) -> &mut NamedAnyMap;

    /// Add a linked observer
    fn add_observer(&mut self, observer: Box<dyn Observer>, name: &'static str) {
        self.observers_mut().push(observer);
    }

    /// Reset the state of all the observes linked to this executor
    fn reset_observers(&mut self) -> Result<(), AflError> {
        for observer in self.observers_mut() {
            observer.reset()?;
        }
        Ok(())
    }

    /// Run the post exec hook for all the observes linked to this executor
    fn post_exec_observers(&mut self) -> Result<(), AflError> {
        self.observers_mut()
            .iter()
            .map(|x| x.post_exec())
            .fold(Ok(()), |acc, x| if x.is_err() { x } else { acc })
    }
}
