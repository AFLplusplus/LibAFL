//! Grimoire is the rewritten grimoire mutator in rust.
//! See the original repo [`Grimoire`](https://github.com/RUB-SysSec/grimoire) for more details.

use core::cmp::{max, min};

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
const CHOOSE_SUBINPUT_PROB: u64 = 50;

fn extend_with_random_generalized<S>(
    state: &mut S,
    items: &mut Vec<GeneralizedItem>,
    gap_indices: &mut Vec<usize>,
) -> Result<bool, Error>
where
    S: HasRand + HasCorpus<GeneralizedInput>,
{
    let count = state.corpus().count();
    let idx = state.rand_mut().below(count as u64) as usize;

    // TODO store as metadata an HashSet of corpus idx that are generalized
    if state
        .corpus()
        .get(idx)?
        .borrow_mut()
        .load_input()?
        .generalized()
        .is_none()
    {
        return Ok(true);
    }

    if state.rand_mut().below(100) > CHOOSE_SUBINPUT_PROB {
        if state.rand_mut().below(100) < 50 {
            let rand1 = state.rand_mut().next() as usize;
            let rand2 = state.rand_mut().next() as usize;

            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other = other_testcase.load_input()?;

            if other.generalized_len() > 0 {
                let gen = other.generalized().unwrap();

                for (i, _) in gen
                    .iter()
                    .enumerate()
                    .filter(|&(_, x)| *x == GeneralizedItem::Gap)
                {
                    gap_indices.push(i);
                }
                let min_idx = gap_indices[rand1 % gap_indices.len()];
                let max_idx = gap_indices[rand2 % gap_indices.len()];
                let (min_idx, max_idx) = (min(min_idx, max_idx), max(min_idx, max_idx));

                gap_indices.clear();

                // TODO check that starts and ends with a Gap
                items.extend_from_slice(&gen[min_idx..max_idx + 1]);

                return Ok(false);
            }
        }

        // TODO get random token
    }

    let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
    let other = other_testcase.load_input()?;
    let gen = other.generalized().unwrap();

    items.extend_from_slice(&gen);

    Ok(false)
}

/// Extend the generalized input with another random one from the corpus
#[derive(Debug, Default)]
pub struct GrimoireExtensionMutator {
    gap_indices: Vec<usize>,
}

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

        // TODO trim input if ending with Gap
        if extend_with_random_generalized(
            state,
            input.generalized_mut().as_mut().unwrap(),
            &mut self.gap_indices,
        )? {
            Ok(MutationResult::Skipped)
        } else {
            Ok(MutationResult::Mutated)
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
        Self {
            gap_indices: vec![],
        }
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

            self.scratch.extend_from_slice(&gen[selected + 1..]);
            gen.truncate(selected);

            if !extend_with_random_generalized(state, gen, &mut self.gap_indices)? {
                mutated = MutationResult::Mutated;
            }

            gen.extend_from_slice(&self.scratch);
            self.scratch.clear();
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
