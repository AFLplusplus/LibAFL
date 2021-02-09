pub mod scheduled;
pub use scheduled::*;
pub mod mutations;
pub use mutations::*;
pub mod token_mutations;
pub use token_mutations::*;

use crate::{
    corpus::Corpus,
    inputs::Input,
    state::{HasCorpus, HasMetadata},
    utils::Rand,
    AflError,
};

// TODO mutator stats method that produces something that can be sent with the NewTestcase event
// We can use it to report which mutations generated the testcase in the broker logs

/// A mutator takes input, and mutates it.
/// Simple as that.
pub trait Mutator<C, I, R, S>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
    S: HasCorpus<C> + HasMetadata,
{
    /// Mutate a given input
    fn mutate(
        &mut self,
        rand: &mut R,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<(), AflError>;

    /// Post-process given the outcome of the execution
    fn post_exec(
        &mut self,
        _state: &mut S,
        _is_interesting: u32,
        _input: &I,
        _stage_idx: i32,
    ) -> Result<(), AflError> {
        Ok(())
    }
}

/// The maximum size of a testcase
pub const DEFAULT_MAX_SIZE: usize = 1048576;

/// Interact with the maximum size
pub trait HasMaxSize {
    /// The maximum size of the contents returned
    fn max_size(&self) -> usize;
    /// Sets the maximum size of the contents returned
    fn set_max_size(&mut self, max_size: usize);
}
