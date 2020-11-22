pub mod scheduled;
pub use scheduled::ComposedByMutations;
pub use scheduled::DefaultScheduledMutator;
pub use scheduled::HavocBytesMutator;
pub use scheduled::ScheduledMutator;

use crate::corpus::{Corpus, HasCorpus};
//use crate::engines::State;
use crate::inputs::Input;
use crate::utils::{HasRand, Rand};
use crate::AflError;

pub trait Mutator<S, C, I, R>
where
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Mutate a given input
    fn mutate(&mut self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<(), AflError>;

    /// Post-process given the outcome of the execution
    fn post_exec(&mut self, _is_interesting: bool, _stage_idx: i32) -> Result<(), AflError> {
        Ok(())
    }
}
