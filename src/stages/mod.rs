extern crate alloc;
pub mod mutational;
use crate::corpus::Corpus;
pub use mutational::DefaultMutationalStage;

use crate::inputs::Input;
use crate::AflError;

pub trait Stage<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    /// Run the stage
    fn perform(&mut self, corpus: &mut C) -> Result<(), AflError>;
}
