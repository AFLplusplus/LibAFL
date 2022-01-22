//! Gramatron is the rewritten gramatron fuzzer in rust.
//! See the original gramatron repo [`Gramatron`](https://github.com/HexHive/Gramatron) for more details.
use alloc::vec::Vec;
use core::cmp::max;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{rands::Rand, tuples::Named},
    corpus::Corpus,
    generators::GramatronGenerator,
    inputs::{GramatronInput, Terminal},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

/// A random mutator for grammar fuzzing
#[derive(Debug)]
pub struct GramatronRandomMutator<'a, S>
where
    S: HasRand + HasMetadata,
{
    generator: &'a GramatronGenerator<'a, S>,
}

impl<'a, S> Mutator<GramatronInput, S> for GramatronRandomMutator<'a, S>
where
    S: HasRand + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut GramatronInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !input.terminals().is_empty() {
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

impl<'a, S> Named for GramatronRandomMutator<'a, S>
where
    S: HasRand + HasMetadata,
{
    fn name(&self) -> &str {
        "GramatronRandomMutator"
    }
}

impl<'a, S> GramatronRandomMutator<'a, S>
where
    S: HasRand + HasMetadata,
{
    /// Creates a new [`GramatronRandomMutator`].
    #[must_use]
    pub fn new(generator: &'a GramatronGenerator<'a, S>) -> Self {
        Self { generator }
    }
}

/// The metadata used for `gramatron`
#[derive(Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct GramatronIdxMapMetadata {
    pub map: HashMap<usize, Vec<usize>>,
}

crate::impl_serdeany!(GramatronIdxMapMetadata);

impl GramatronIdxMapMetadata {
    /// Creates a new [`struct@GramatronIdxMapMetadata`].
    #[must_use]
    pub fn new(input: &GramatronInput) -> Self {
        let mut map = HashMap::default();
        for i in 0..input.terminals().len() {
            let entry = map.entry(input.terminals()[i].state).or_insert(vec![]);
            (*entry).push(i);
        }
        Self { map }
    }
}

/// A [`Mutator`] that mutates a [`GramatronInput`] by splicing inputs together.
#[derive(Default, Debug)]
pub struct GramatronSpliceMutator;

impl<S> Mutator<GramatronInput, S> for GramatronSpliceMutator
where
    S: HasRand + HasCorpus<GramatronInput> + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut GramatronInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.terminals().is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;

        let insert_at = state.rand_mut().below(input.terminals().len() as u64) as usize;

        let rand_num = state.rand_mut().next() as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        other_testcase.load_input()?; // Preload the input

        if !other_testcase.has_metadata::<GramatronIdxMapMetadata>() {
            let meta = GramatronIdxMapMetadata::new(other_testcase.input().as_ref().unwrap());
            other_testcase.add_metadata(meta);
        }
        let meta = other_testcase
            .metadata()
            .get::<GramatronIdxMapMetadata>()
            .unwrap();
        let other = other_testcase.input().as_ref().unwrap();

        meta.map.get(&input.terminals()[insert_at].state).map_or(
            Ok(MutationResult::Skipped),
            |splice_points| {
                let from = splice_points[rand_num % splice_points.len()];

                input.terminals_mut().truncate(insert_at);
                input
                    .terminals_mut()
                    .extend_from_slice(&other.terminals()[from..]);

                Ok(MutationResult::Mutated)
            },
        )
    }
}

impl Named for GramatronSpliceMutator {
    fn name(&self) -> &str {
        "GramatronSpliceMutator"
    }
}

impl GramatronSpliceMutator {
    /// Creates a new [`GramatronSpliceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// A mutator that uses Gramatron for grammar fuzzing and mutation.
#[derive(Default, Debug)]
pub struct GramatronRecursionMutator {
    counters: HashMap<usize, (usize, usize, usize)>,
    states: Vec<usize>,
    temp: Vec<Terminal>,
}

impl<S> Mutator<GramatronInput, S> for GramatronRecursionMutator
where
    S: HasRand + HasMetadata,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut GramatronInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.terminals().is_empty() {
            return Ok(MutationResult::Skipped);
        }

        self.counters.clear();
        self.states.clear();
        for i in 0..input.terminals().len() {
            let s = input.terminals()[i].state;
            if let Some(entry) = self.counters.get_mut(&s) {
                if entry.0 == 1 {
                    // Keep track only of states with more than one node
                    self.states.push(s);
                }
                entry.0 += 1;
                entry.2 = max(entry.2, i);
            } else {
                self.counters.insert(s, (1, i, i));
            }
        }

        if self.states.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let chosen = *state.rand_mut().choose(&self.states);
        let chosen_nums = self.counters.get(&chosen).unwrap().0;

        #[allow(clippy::cast_sign_loss, clippy::pedantic)]
        let mut first = state.rand_mut().below(chosen_nums as u64 - 1) as i64;
        #[allow(clippy::cast_sign_loss, clippy::pedantic)]
        let mut second = state
            .rand_mut()
            .between(first as u64 + 1, chosen_nums as u64 - 1) as i64;

        let mut idx_1 = 0;
        let mut idx_2 = 0;
        for i in (self.counters.get(&chosen).unwrap().1)..=(self.counters.get(&chosen).unwrap().2) {
            if input.terminals()[i].state == chosen {
                if first == 0 {
                    idx_1 = i;
                }
                if second == 0 {
                    idx_2 = i;
                    break;
                }
                first -= 1;
                second -= 1;
            }
        }
        debug_assert!(idx_1 < idx_2);

        self.temp.clear();
        self.temp.extend_from_slice(&input.terminals()[idx_2..]);

        input.terminals_mut().truncate(idx_2);
        input.terminals_mut().extend_from_slice(&self.temp);

        Ok(MutationResult::Mutated)
    }
}

impl Named for GramatronRecursionMutator {
    fn name(&self) -> &str {
        "GramatronRecursionMutator"
    }
}

impl GramatronRecursionMutator {
    /// Creates a new [`GramatronRecursionMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
