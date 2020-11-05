pub mod inmemory;

use crate::inputs::Input;
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
    fn run_target(&mut self, input: &mut I) -> Result<ExitKind, AflError>;

    /// Reset the state of all the observes linked to this executor
    fn reset_observers(&mut self) -> Result<(), AflError>;

    /// Run the post exec hook for all the observes linked to this executor
    fn post_exec_observers(&mut self) -> Result<(), AflError>;

    /// Add a linked observer
    fn add_observer(&mut self, observer: Box<dyn Observer>);

    /// Get the linked observers
    fn observers(&self) -> &Vec<Box<dyn Observer>>;
}
