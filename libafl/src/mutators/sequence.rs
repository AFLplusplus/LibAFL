//! Mutators for `SequenceInput`

use alloc::vec::Vec;

use crate::{
    bolts::{rands::Rand, tuples::Named},
    inputs::{Input, SequenceInput},
    mutators::{MutationResult, Mutator},
    Error,
};

/// Extend the generalized input with another random one from the corpus
#[derive(Debug, Default)]
pub struct SequenceRandomMutator<M> {
    inner: M,
}

impl<M, I, S> Mutator<SequenceInput<I>, S> for SequenceRandomMutator<M>
where
    I: Input,
    M: Mutator<I, S>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut SequenceInput<I>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.seq().is_empty() {
            return Ok(MutationResult::Skipped);
        }

        //....
        Ok(MutationResult::Mutated)
    }
}

impl<M> Named for SequenceRandomMutator<M> {
    fn name(&self) -> &str {
        "SequenceRandomMutator"
    }
}

impl<M> SequenceRandomMutator<M> {
    /// Creates a new [`GrimoireExtensionMutator`].
    #[must_use]
    pub fn new<I, S>(inner: M) -> Self
    where
        I: Input,
        M: Mutator<I, S>,
    {
        Self { inner }
    }
}
