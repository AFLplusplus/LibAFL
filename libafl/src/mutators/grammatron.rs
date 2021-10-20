use core::marker::PhantomData;

use crate::{
    bolts::{rands::Rand, tuples::Named},
    corpus::Corpus,
    generators::GrammatronGenerator,
    inputs::GrammatronInput,
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

pub struct GrammatronRandomMutator<'a, R, S>
where
    S: HasRand<R> + HasMetadata,
    R: Rand,
{
    generator: &'a GrammatronGenerator<R, S>,
    phantom: PhantomData<(R, S)>,
}

impl<'a, R, S> Mutator<GrammatronInput, S> for GrammatronRandomMutator<'a, R, S>
where
    S: HasRand<R> + HasMetadata,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut GrammatronInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.terminals().len() > 0 {
            let size = state.rand_mut().below(input.terminals().len() as u64 + 1) as usize;
            input.terminals_mut().truncate(size);
        }
        if self.generator.append_generated_terminals(input, state) > 0 {
            Ok(MutationResult::Mutated)
        } else {
            Ok(MutationResult::Skipped)
        }
    }
}

impl<'a, R, S> Named for GrammatronRandomMutator<'a, R, S>
where
    S: HasRand<R> + HasMetadata,
    R: Rand,
{
    fn name(&self) -> &str {
        "GrammatronRandomMutator"
    }
}

impl<'a, R, S> GrammatronRandomMutator<'a, R, S>
where
    S: HasRand<R> + HasMetadata,
    R: Rand,
{
    /// Creates a new [`GrammatronRandomMutator`].
    #[must_use]
    pub fn new(generator: &'a GrammatronGenerator<R, S>) -> Self {
        Self {
            generator,
            phantom: PhantomData,
        }
    }
}
