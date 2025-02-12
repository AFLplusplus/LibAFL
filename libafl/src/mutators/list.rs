//! Mutators for [`ListInput`]
use alloc::borrow::Cow;
use core::num::NonZero;

use libafl_bolts::{rands::Rand as _, Error, Named};

use crate::{
    generators::Generator,
    inputs::ListInput,
    mutators::{MutationResult, Mutator},
    state::HasRand,
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

/// Mutator that removes the last entry from a [`ListInput`].
///
/// Returns [`MutationResult::Skipped`] if the input is empty.
#[derive(Debug)]
pub struct RemoveLastEntryMutator;

impl<I, S> Mutator<ListInput<I>, S> for RemoveLastEntryMutator {
    fn mutate(
        &mut self,
        _state: &mut S,
        input: &mut ListInput<I>,
    ) -> Result<MutationResult, Error> {
        match input.parts_mut().pop() {
            Some(_) => Ok(MutationResult::Mutated),
            None => Ok(MutationResult::Skipped),
        }
    }
}

impl Named for RemoveLastEntryMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("RemoveLastEntryMutator")
    }
}

/// Mutator that removes a random entry from a [`ListInput`].
///
/// Returns [`MutationResult::Skipped`] if the input is empty.
#[derive(Debug)]
pub struct RemoveRandomEntryMutator;

impl<I, S> Mutator<ListInput<I>, S> for RemoveRandomEntryMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut ListInput<I>) -> Result<MutationResult, Error> {
        let parts = input.parts_mut();
        match parts.len() {
            0 => Ok(MutationResult::Skipped),
            len => {
                // Safety: null checks are done above
                let index = state
                    .rand_mut()
                    .below(unsafe { NonZero::new_unchecked(len) });
                parts.remove(index);
                Ok(MutationResult::Mutated)
            }
        }
    }
}

impl Named for RemoveRandomEntryMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("RemoveRandomEntryMutator")
    }
}
