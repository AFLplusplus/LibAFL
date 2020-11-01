use crate::inputs::Input;
use crate::utils::{Rand, HasRand};
use crate::corpus::Corpus;
use crate::AflError;

pub mod scheduled;
pub use scheduled::{ComposedByMutations, ScheduledMutator, HavocBytesMutator};

pub trait Mutator<InputT : Input, RandT: Rand> : HasRand<RandT> {
    /// Mutate a given input
    fn mutate(&mut self, input: &mut InputT, stage_idx: i32) -> Result<(), AflError>;

    /// Post-process given the outcome of the execution
    fn post_exec(&mut self, _is_interesting: bool, _stage_idx: i32) -> Result<(), AflError> {
        Ok(())
    }

    /// Get the associated corpus, if any
    fn corpus(&mut self) -> &mut Option<Box<dyn Corpus<InputT, RandT>>>;
}
