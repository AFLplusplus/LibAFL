pub mod scheduled;
pub use scheduled::*;
pub mod mutations;
pub use mutations::*;

use crate::corpus::Corpus;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;

pub trait Mutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Mutate a given input
    fn mutate(
        &mut self,
        rand: &mut R,
        corpus: &C,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<(), AflError>;

    /// Post-process given the outcome of the execution
    fn post_exec(
        &mut self,
        _is_interesting: u32,
        _input: &I,
        _stage_idx: i32,
    ) -> Result<(), AflError> {
        Ok(())
    }
}

pub const DEFAULT_MAX_SIZE: usize = 1048576;

pub trait HasMaxSize {
    fn max_size(&self) -> usize;
    fn set_max_size(&mut self, max_size: usize);
}
