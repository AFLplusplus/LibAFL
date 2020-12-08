pub mod inmemory;

use crate::inputs::Input;
use crate::serde_anymap::NamedSerdeAnyMap;
use crate::observers::Observer;
use crate::AflError;

pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout,
}

pub trait Executor<I>
where
    I: Input,
{
    /// Instruct the target about the input and run
    fn run_target(&mut self, input: &I) -> Result<ExitKind, AflError>;

    /// Get the linked observers
    fn observers(&self) -> &NamedSerdeAnyMap<dyn Observer>;

    /// Get the linked observers
    fn observers_mut(&mut self) -> &mut NamedSerdeAnyMap<dyn Observer>;

    /// Add a linked observer
    fn add_observer(&mut self, observer: Box<dyn Observer>) {
        let name = observer.name();
        self.observers_mut().insert(observer, name);
    }

    /// Reset the state of all the observes linked to this executor
    fn reset_observers(&mut self) -> Result<(), AflError> {
        self.observers_mut().for_each_mut(|_, x| Ok(x.reset()?))?;
        Ok(())
    }

    /// Run the post exec hook for all the observes linked to this executor
    fn post_exec_observers(&mut self) -> Result<(), AflError> {
        self.observers_mut().for_each_mut(|_, x| Ok(x.post_exec()?))?;
        Ok(())
    }
}
