//! Grimoire is the rewritten grimoire mutator in rust.
//! See the original repo [`Grimoire`](https://github.com/RUB-SysSec/grimoire) for more details.

use alloc::vec::Vec;
use core::cmp::{max, min};

use crate::{
    bolts::{rands::Rand, tuples::Named},
    corpus::Corpus,
    inputs::{GeneralizedInput, GeneralizedItem},
    mutators::{token_mutations::Tokens, MutationResult, Mutator},
    stages::generalization::GeneralizedIndexesMetadata,
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

const RECURSIVE_REPLACEMENT_DEPTH: [usize; 6] = [2, 4, 8, 16, 32, 64];
const MAX_RECURSIVE_REPLACEMENT_LEN: usize = 64 << 10;
const CHOOSE_SUBINPUT_PROB: u64 = 50;

fn extend_with_random_generalized<S>(
    state: &mut S,
    items: &mut Vec<GeneralizedItem>,
    gap_indices: &mut Vec<usize>,
) -> Result<(), Error>
where
    S: HasMetadata + HasRand + HasCorpus<GeneralizedInput>,
{
    let rand_idx = state.rand_mut().next() as usize;

    let idx = {
        let meta = state.metadata_mut().get_mut::<GeneralizedIndexesMetadata>().ok_or_else(|| {
            Error::KeyNotFound("GeneralizedIndexesMetadata needed by extend_with_random_generalized() not found, make sure that you have GeneralizationStage in".into())
        })?;

        *meta
            .indexes
            .iter()
            .nth(rand_idx % meta.indexes.len())
            .unwrap()
    };

    /*if state
        .corpus()
        .get(idx)?
        .borrow_mut()
        .load_input()?
        .generalized()
        .is_none()
    {
        return Ok(true);
    }*/

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
                let (mut min_idx, max_idx) = (min(min_idx, max_idx), max(min_idx, max_idx));

                gap_indices.clear();

                if items.last() == Some(&GeneralizedItem::Gap) {
                    min_idx += 1;
                }
                items.extend_from_slice(&gen[min_idx..=max_idx]);

                debug_assert!(items.first() == Some(&GeneralizedItem::Gap));
                debug_assert!(items.last() == Some(&GeneralizedItem::Gap));

                return Ok(());
            }
        }

        let rand1 = state.rand_mut().next() as usize;

        if let Some(meta) = state.metadata().get::<Tokens>() {
            if !meta.tokens().is_empty() {
                let tok = &meta.tokens()[rand1 % meta.tokens().len()];
                if items.last() != Some(&GeneralizedItem::Gap) {
                    items.push(GeneralizedItem::Gap);
                }
                items.push(GeneralizedItem::Bytes(tok.clone()));
                items.push(GeneralizedItem::Gap);

                debug_assert!(items.first() == Some(&GeneralizedItem::Gap));
                debug_assert!(items.last() == Some(&GeneralizedItem::Gap));

                return Ok(());
            }
        }
    }

    let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
    let other = other_testcase.load_input()?;
    let gen = other.generalized().unwrap();

    if items.last() == Some(&GeneralizedItem::Gap) && gen.first() == Some(&GeneralizedItem::Gap) {
        items.extend_from_slice(&gen[1..]);
    } else {
        items.extend_from_slice(gen);
    }

    debug_assert!(items.first() == Some(&GeneralizedItem::Gap));
    debug_assert!(items.last() == Some(&GeneralizedItem::Gap));

    Ok(())
}

/// Extend the generalized input with another random one from the corpus
#[derive(Debug, Default)]
pub struct GrimoireExtensionMutator {
    gap_indices: Vec<usize>,
}

impl<S> Mutator<GeneralizedInput, S> for GrimoireExtensionMutator
where
    S: HasMetadata + HasRand + HasCorpus<GeneralizedInput>,
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

        extend_with_random_generalized(
            state,
            input.generalized_mut().as_mut().unwrap(),
            &mut self.gap_indices,
        )?;

        input.grimoire_mutated = true;
        Ok(MutationResult::Mutated)
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
    S: HasMetadata + HasRand + HasCorpus<GeneralizedInput>,
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
            if input.generalized_len() >= MAX_RECURSIVE_REPLACEMENT_LEN {
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

            extend_with_random_generalized(state, gen, &mut self.gap_indices)?;

            gen.extend_from_slice(&self.scratch);
            self.scratch.clear();

            mutated = MutationResult::Mutated;
            input.grimoire_mutated = true;
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

/// Replace matching tokens with others from the tokens metadata
#[derive(Debug, Default)]
pub struct GrimoireStringReplacementMutator {}

impl<S> Mutator<GeneralizedInput, S> for GrimoireStringReplacementMutator
where
    S: HasMetadata + HasRand,
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

        let tokens_len = {
            let meta = state.metadata().get::<Tokens>();
            if meta.is_none() {
                return Ok(MutationResult::Skipped);
            }
            if meta.unwrap().tokens().is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.unwrap().tokens().len()
        };
        let token_find = state.rand_mut().below(tokens_len as u64) as usize;
        let mut token_replace = state.rand_mut().below(tokens_len as u64) as usize;
        if token_find == token_replace {
            token_replace = state.rand_mut().below(tokens_len as u64) as usize;
        }

        let stop_at_first = state.rand_mut().below(100) > 50;
        let mut rand_idx = state.rand_mut().next() as usize;

        let meta = state.metadata().get::<Tokens>().unwrap();
        let token_1 = &meta.tokens()[token_find];
        let token_2 = &meta.tokens()[token_replace];

        let mut mutated = MutationResult::Skipped;

        let gen = input.generalized_mut().as_mut().unwrap();
        rand_idx %= gen.len();

        'first: for item in &mut gen[..rand_idx] {
            if let GeneralizedItem::Bytes(bytes) = item {
                if bytes.len() < token_1.len() {
                    continue;
                }
                for i in 0..(bytes.len() - token_1.len()) {
                    if bytes[i..].starts_with(token_1) {
                        bytes.splice(i..(i + token_1.len()), token_2.clone());

                        mutated = MutationResult::Mutated;
                        if stop_at_first {
                            break 'first;
                        }
                    }
                }
            }
        }
        if mutated == MutationResult::Skipped || !stop_at_first {
            'second: for item in &mut gen[rand_idx..] {
                if let GeneralizedItem::Bytes(bytes) = item {
                    if bytes.len() < token_1.len() {
                        continue;
                    }
                    for i in 0..(bytes.len() - token_1.len()) {
                        if bytes[i..].starts_with(token_1) {
                            bytes.splice(i..(i + token_1.len()), token_2.clone());

                            mutated = MutationResult::Mutated;
                            if stop_at_first {
                                break 'second;
                            }
                        }
                    }
                }
            }
        }

        input.grimoire_mutated = true;
        Ok(mutated)
    }
}

impl Named for GrimoireStringReplacementMutator {
    fn name(&self) -> &str {
        "GrimoireStringReplacementMutator"
    }
}

impl GrimoireStringReplacementMutator {
    /// Creates a new [`GrimoireExtensionMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Randomly delete a part of the generalized input
#[derive(Debug, Default)]
pub struct GrimoireRandomDeleteMutator {
    gap_indices: Vec<usize>,
}

impl<S> Mutator<GeneralizedInput, S> for GrimoireRandomDeleteMutator
where
    S: HasMetadata + HasRand + HasCorpus<GeneralizedInput>,
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

        input.grimoire_mutated = true;
        let gen = input.generalized_mut().as_mut().unwrap();

        for (i, _) in gen
            .iter()
            .enumerate()
            .filter(|&(_, x)| *x == GeneralizedItem::Gap)
        {
            self.gap_indices.push(i);
        }
        let min_idx =
            self.gap_indices[state.rand_mut().below(self.gap_indices.len() as u64) as usize];
        let max_idx =
            self.gap_indices[state.rand_mut().below(self.gap_indices.len() as u64) as usize];
        let (min_idx, max_idx) = (min(min_idx, max_idx), max(min_idx, max_idx));

        self.gap_indices.clear();

        if min_idx == max_idx {
            Ok(MutationResult::Skipped)
        } else {
            gen.drain(min_idx..max_idx);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for GrimoireRandomDeleteMutator {
    fn name(&self) -> &str {
        "GrimoireRandomDeleteMutator"
    }
}

impl GrimoireRandomDeleteMutator {
    /// Creates a new [`GrimoireExtensionMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            gap_indices: vec![],
        }
    }
}
