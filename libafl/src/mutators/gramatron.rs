use alloc::vec::Vec;
use core::marker::PhantomData;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{rands::Rand, tuples::Named},
    corpus::Corpus,
    generators::GramatronGenerator,
    inputs::GramatronInput,
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

pub struct GramatronRandomMutator<'a, R, S>
where
    S: HasRand<R> + HasMetadata,
    R: Rand,
{
    generator: &'a GramatronGenerator<R, S>,
}

impl<'a, R, S> Mutator<GramatronInput, S> for GramatronRandomMutator<'a, R, S>
where
    S: HasRand<R> + HasMetadata,
    R: Rand,
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

impl<'a, R, S> Named for GramatronRandomMutator<'a, R, S>
where
    S: HasRand<R> + HasMetadata,
    R: Rand,
{
    fn name(&self) -> &str {
        "GramatronRandomMutator"
    }
}

impl<'a, R, S> GramatronRandomMutator<'a, R, S>
where
    S: HasRand<R> + HasMetadata,
    R: Rand,
{
    /// Creates a new [`GramatronRandomMutator`].
    #[must_use]
    pub fn new(generator: &'a GramatronGenerator<R, S>) -> Self {
        Self { generator }
    }
}

#[derive(Serialize, Deserialize)]
struct GramatronIdxMapMetadata {
    pub map: HashMap<usize, Vec<usize>>,
}

crate::impl_serdeany!(GramatronIdxMapMetadata);

impl GramatronIdxMapMetadata {
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

pub struct GramatronSpliceMutator<C, R, S>
where
    C: Corpus<GramatronInput>,
    S: HasRand<R> + HasCorpus<C, GramatronInput> + HasMetadata,
    R: Rand,
{
    phantom: PhantomData<(C, R, S)>,
}

impl<C, R, S> Mutator<GramatronInput, S> for GramatronSpliceMutator<C, R, S>
where
    C: Corpus<GramatronInput>,
    S: HasRand<R> + HasCorpus<C, GramatronInput> + HasMetadata,
    R: Rand,
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

impl<C, R, S> Named for GramatronSpliceMutator<C, R, S>
where
    C: Corpus<GramatronInput>,
    S: HasRand<R> + HasCorpus<C, GramatronInput> + HasMetadata,
    R: Rand,
{
    fn name(&self) -> &str {
        "GramatronSpliceMutator"
    }
}

impl<'a, C, R, S> GramatronSpliceMutator<C, R, S>
where
    C: Corpus<GramatronInput>,
    S: HasRand<R> + HasCorpus<C, GramatronInput> + HasMetadata,
    R: Rand,
{
    /// Creates a new [`GramatronSpliceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
