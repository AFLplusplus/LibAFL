use crate::corpus::Corpus;
use crate::inputs::Input;
use crate::utils::HasRand;
use crate::AflError;

pub mod scheduled;

pub trait HasOptionCorpus<I>
where
    I: Input,
{
    type C: Corpus<I>;

    /// Get the associated corpus, if any
    fn corpus(&self) -> &Option<Box<Self::C>>;

    /// Get the associated corpus, if any (mutable)
    fn corpus_mut(&mut self) -> &mut Option<Box<Self::C>>;

    /// Set the associated corpus
    fn set_corpus(&mut self, corpus: Option<Box<Self::C>>);
}

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
