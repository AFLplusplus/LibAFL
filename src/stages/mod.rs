pub mod mutational;

use crate::corpus::Testcase;
use crate::inputs::Input;
use crate::engines::Engine;
use crate::AflError;

pub trait HasEngine<'a, I> where I: Input {
    type E : Engine<'a, I>;

    fn engine(&self) -> &Self::E;

    fn engine_mut(&mut self) -> &mut Self::E;
}

pub trait Stage<'a, I> : HasEngine<'a, I> where I: Input {
    /// Run the stage
    fn perform(&mut self, entry: &mut Testcase<I>) -> Result<(), AflError>;
}
