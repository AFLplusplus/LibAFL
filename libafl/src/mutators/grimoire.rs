//! Grimoire is the rewritten grimoire mutator in rust.
//! See the original repo [`Grimoire`](https://github.com/RUB-SysSec/grimoire) for more details.

use crate::{
    bolts::{rands::Rand, tuples::Named},
    corpus::Corpus,
    inputs::GeneralizedInput,
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasRand},
    Error,
};

/// Extend the generalized input with another random one from the corpus
#[derive(Debug, Default)]
pub struct GrimoireExtensionMutator {}

impl<S> Mutator<GeneralizedInput, S> for GrimoireExtensionMutator
where
    S: HasRand + HasCorpus<GeneralizedInput>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut GeneralizedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.generalized().is_none() {
            return Ok(MutationResult::Skipped);
        }

        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input()?;

        // TODO store as metadata an HashSet of corpus idx that are generalized
        match other.generalized() {
            None => Ok(MutationResult::Skipped),
            Some(gen) => {
                input.generalized_extend(gen);
                Ok(MutationResult::Mutated)
            }
        }
    }
}

impl Named for GrimoireExtensionMutator {
    fn name(&self) -> &str {
        "GrimoireExtensionMutator"
    }
}

impl GrimoireExtensionMutator {
    /// Creates a new [`GrimoireExtensionMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}
