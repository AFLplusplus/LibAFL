extern crate alloc;
pub mod scheduled;
pub use scheduled::ComposedByMutations;
pub use scheduled::DefaultScheduledMutator;
pub use scheduled::HavocBytesMutator;
pub use scheduled::ScheduledMutator;

use crate::inputs::Input;
use crate::utils::HasRand;
use crate::AflError;

pub trait Mutator<I>: HasRand
where
    I: Input,
{
    /// Mutate a given input
    fn mutate(&mut self, input: &mut I, stage_idx: i32) -> Result<(), AflError>;

    /// Post-process given the outcome of the execution
    fn post_exec(&mut self, _is_interesting: bool, _stage_idx: i32) -> Result<(), AflError> {
        Ok(())
    }
}
