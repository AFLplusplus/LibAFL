//! Mutations for UTF-8 inputs ([`Utf8Input`]).

use alloc::string::String;

use crate::{
    bolts::{rands::Rand, tuples::Named},
    inputs::utf8::Utf8Input,
    mutators::{
        mutations::{buffer_copy, buffer_self_copy, rand_range},
        MutationResult, Mutator,
    },
    state::{HasMaxSize, HasRand},
    Error,
};

/// Like https://doc.rust-lang.org/std/string/struct.String.html#method.floor_char_boundary
fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    debug_assert!(idx <= s.len());
    // note: 0 is always a char boundary
    while !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Delete a chunk of characters.
///
/// Compare to [`crate::mtuators::mutations::BytesDeleteMutator`].
#[derive(Default, Debug)]
pub struct Utf8DeleteMutator;

impl<S> Mutator<Utf8Input, S> for Utf8DeleteMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut Utf8Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.string.len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        let mut range = rand_range(state, size, size);
        range.start = floor_char_boundary(&input.string, range.start);
        range.end = floor_char_boundary(&input.string, range.end);
        if range.start == range.end {
            return Ok(MutationResult::Skipped);
        }

        input.string.drain(range);
        Ok(MutationResult::Mutated)
    }
}

impl Named for Utf8DeleteMutator {
    fn name(&self) -> &str {
        "Utf8DeleteMutator"
    }
}

/// Pick a random character from the input and insert it.
///
/// Compare to [`crate::mtuators::mutations::BytesInsertMutator`].
#[derive(Default, Debug)]
pub struct Utf8InsertMutator;

impl<S> Mutator<Utf8Input, S> for Utf8InsertMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut Utf8Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.string.len();
        if size == 0 || size >= max_size {
            return Ok(MutationResult::Skipped);
        }

        let mut amount = 1 + state.rand_mut().below(16) as usize;
        let mut offset = state.rand_mut().below(size as u64 + 1) as usize;
        offset = floor_char_boundary(&input.string, offset);

        if size + amount > max_size {
            if max_size > size {
                amount = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        let chars = input.string.chars().count();
        let val = input
            .string
            .chars()
            .nth(state.rand_mut().below(chars as u64) as usize)
            .unwrap();

        let inserted_bytes = val.len_utf8() * amount;
        let mut repeated = String::with_capacity(inserted_bytes);
        for _ in 0..amount {
            repeated.push(val);
        }

        unsafe {
            let vec = input.string.as_mut_vec();
            vec.resize(size + inserted_bytes, 0);
            buffer_self_copy(vec, offset, offset + inserted_bytes, size - offset);
            buffer_copy(vec, repeated.as_bytes(), 0, offset, repeated.len());
        }

        Ok(MutationResult::Mutated)
    }
}

impl Named for Utf8InsertMutator {
    fn name(&self) -> &str {
        "Utf8InsertMutator"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        alloc::string::ToString,
        bolts::{
            rands::StdRand,
            tuples::{tuple_list, HasConstLen},
        },
        corpus::{Corpus, InMemoryCorpus},
        feedbacks::ConstFeedback,
        inputs::utf8::Utf8Input,
        mutators::MutatorsTuple,
        state::{HasCorpus, HasMetadata, StdState},
    };

    fn test_utf8_mutations<S>() -> impl MutatorsTuple<Utf8Input, S>
    where
        S: HasRand + HasMetadata + HasMaxSize,
    {
        tuple_list!(Utf8DeleteMutator::default(), Utf8InsertMutator::default())
    }

    fn test_state() -> impl HasCorpus + HasMetadata + HasRand + HasMaxSize {
        let rand = StdRand::with_seed(1337);
        let mut corpus = InMemoryCorpus::new();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        corpus
            .add(Utf8Input::new("hello, world!".to_string()).into())
            .unwrap();

        StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    }

    #[test]
    #[cfg_attr(miri, ignore)] // testing all mutators would be good but is way too slow. :/
    fn test_utf8_mutators() {
        let mut inputs = vec![
            Utf8Input::new("hello".to_string()),
            Utf8Input::new("LibAFL".to_string()),
            Utf8Input::new("0xbad1dea".to_string()),
        ];

        let mut state = test_state();

        let mut mutations = test_utf8_mutations();

        for _ in 0..2 {
            let mut new_testcases = vec![];
            for idx in 0..mutations.len() {
                for input in &inputs {
                    let mut mutant = input.clone();
                    match mutations
                        .get_and_mutate(idx.into(), &mut state, &mut mutant, 0)
                        .unwrap()
                    {
                        MutationResult::Mutated => new_testcases.push(mutant),
                        MutationResult::Skipped => (),
                    };
                }
            }
            inputs.append(&mut new_testcases);
        }
    }
}
