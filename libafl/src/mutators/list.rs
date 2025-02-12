//! Mutators for [`ListInput`]
use alloc::borrow::Cow;

use libafl_bolts::{Error, Named};

use crate::{
    generators::Generator,
    inputs::ListInput,
    mutators::{MutationResult, Mutator},
};

/// Mutator that generates a new input and appends it to the list.
#[derive(Debug)]
pub struct GenerateToAppendMutator<G> {
    generator: G,
}

impl<G> GenerateToAppendMutator<G> {
    /// Create a new `GenerateToAppendMutator`.
    #[must_use]
    pub fn new(generator: G) -> Self {
        Self { generator }
    }
}

impl<G, I, S> Mutator<ListInput<I>, S> for GenerateToAppendMutator<G>
where
    G: Generator<I, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut ListInput<I>) -> Result<MutationResult, Error> {
        let generated = self.generator.generate(state)?;
        input.parts_mut().push(generated);
        Ok(MutationResult::Mutated)
    }
}

impl<G> Named for GenerateToAppendMutator<G> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("GenerateToAppendMutator")
    }
}
