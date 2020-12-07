pub mod inmemory;

use crate::inputs::Input;
use crate::metamap::NamedAnyMap;
use crate::observers::Observer;
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
    fn observers(&self) -> &NamedAnyMap<dyn Observer>;

    /// Get the linked observers
    fn observers_mut(&mut self) -> &mut NamedAnyMap<dyn Observer>;

    /// Add a linked observer
    fn add_observer(&mut self, observer: Box<dyn Observer>) {
        self.observers_mut().insert(observer, observer.name());
    }

    /// Reset the state of all the observes linked to this executor
    fn reset_observers(&mut self) -> Result<(), AflError> {
        for typeid in self.observers().all_typeids() {
            for observer in self.observers_mut().all_by_typeid_mut(typeid).unwrap() {
                observer.reset()?;
            }
        }
        Ok(())
    }

    /// Run the post exec hook for all the observes linked to this executor
    fn post_exec_observers(&mut self) -> Result<(), AflError> {
        for typeid in self.observers().all_typeids() {
            for observer in self.observers_mut().all_by_typeid_mut(typeid).unwrap() {
                observer.post_exec()?;
            }
        }
        Ok(())
    }
}
