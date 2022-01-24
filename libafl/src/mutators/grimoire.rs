//! Grimoire is the rewritten grimoire mutator in rust.
//! See the original repo [`Grimoire`](https://github.com/RUB-SysSec/grimoire) for more details.

use crate::{
    bolts::{rands::Rand, tuples::Named},
    corpus::Corpus,
    inputs::{GeneralizedInput, GeneralizedItem},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasRand},
    Error,
};

const RECURSIVE_REPLACEMENT_DEPTH: [usize; 6] = [2, 4, 8, 16, 32, 64];
const MAX_RECURSIVE_REPLACEMENT_LEN: usize = 64 << 10;

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
                // TODO choose subinput with prob 0.5
                input.generalized_extend(gen);
                input.grimoire_mutated = true;
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

/// Extend the generalized input with another random one from the corpus
#[derive(Debug, Default)]
pub struct GrimoireRecursiveReplacementMutator {
    scratch: Vec<GeneralizedItem>,
    gap_indices: Vec<usize>,
}

impl<S> Mutator<GeneralizedInput, S> for GrimoireRecursiveReplacementMutator
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

        let mut mutated = MutationResult::Skipped;

        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;

        let depth = *state.rand_mut().choose(&RECURSIVE_REPLACEMENT_DEPTH);
        for _ in 0..depth {
            let len = input.generalized_len();
            if len >= MAX_RECURSIVE_REPLACEMENT_LEN {
                break;
            }

            let gen = input.generalized_mut().as_mut().unwrap();

            for (i, _) in gen
                .iter()
                .enumerate()
                .filter(|&(_, x)| *x == GeneralizedItem::Gap)
            {
                self.gap_indices.push(i);
            }
            let selected = *state.rand_mut().choose(&self.gap_indices);
            self.gap_indices.clear();

            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other = other_testcase.load_input()?;

            if other.generalized().is_none() {
                continue;
            }

            self.scratch.extend_from_slice(&gen[selected + 1..]);

            gen.truncate(selected);
            gen.extend_from_slice(&other.generalized().unwrap());
            gen.extend_from_slice(&self.scratch);

            self.scratch.clear();

            mutated = MutationResult::Mutated;
        }

        Ok(mutated)
    }
}

impl Named for GrimoireRecursiveReplacementMutator {
    fn name(&self) -> &str {
        "GrimoireRecursiveReplacementMutator"
    }
}

impl GrimoireRecursiveReplacementMutator {
    /// Creates a new [`GrimoireRecursiveReplacementMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            scratch: vec![],
            gap_indices: vec![],
        }
    }
}
