use std::cmp::min;

use libafl_bolts::{rands::Rand, Error};
use rand::RngCore;

use crate::{
    corpus::{Corpus, CorpusId},
    inputs::{multi::MultipartInput, HasBytesVec, Input},
    mutators::{
        mutations::*,
        token_mutations::{I2SRandReplace, TokenInsert, TokenReplace},
        MutationResult, Mutator,
    },
    random_corpus_id,
    state::{HasCorpus, HasMaxSize, HasRand},
};
pub trait DefaultMultipartMutator {}

impl<I, M, S> Mutator<MultipartInput<I>, S> for M
where
    M: DefaultMultipartMutator + Mutator<I, S>,
    S: HasRand,
    <S as HasRand>::Rand: RngCore,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if !input.parts().is_empty() {
            let selected = state.rand_mut().below(input.parts().len() as u64) as usize;
            let mutated = input.part_mut(selected).unwrap();
            self.mutate(state, mutated, stage_idx)
        } else {
            Ok(MutationResult::Skipped)
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        M::post_exec(self, state, stage_idx, corpus_idx)
    }
}

#[macro_export]
macro_rules! impl_default_multipart {
    ($mutator: ty, $($mutators: ty),+$(,)?) => {
        impl $crate::mutators::multi::DefaultMultipartMutator for $mutator {}
        impl_default_multipart!($($mutators),+);
    };

    ($mutator: ty) => {
        impl $crate::mutators::multi::DefaultMultipartMutator for $mutator {}
    };
}

impl_default_multipart!(
    // --- havoc ---
    BitFlipMutator,
    ByteAddMutator,
    ByteDecMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteInterestingMutator,
    ByteNegMutator,
    ByteRandMutator,
    BytesCopyMutator,
    BytesDeleteMutator,
    BytesExpandMutator,
    BytesInsertCopyMutator,
    BytesInsertMutator,
    BytesRandInsertMutator,
    BytesRandSetMutator,
    BytesSetMutator,
    BytesSwapMutator,
    // crossover has a custom implementation below
    DwordAddMutator,
    DwordInterestingMutator,
    QwordAddMutator,
    WordAddMutator,
    WordInterestingMutator,
    // --- token ---
    TokenInsert,
    TokenReplace,
    // ---  i2s  ---
    I2SRandReplace,
);

impl<I, S> Mutator<MultipartInput<I>, S> for CrossoverInsertMutator<I>
where
    S: HasCorpus<Input = MultipartInput<I>> + HasMaxSize + HasRand,
    I: Input + HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        // we can eat the slight bias; number of parts will be small
        let next = state.rand_mut().next() as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;

        let choice = next % other.parts().len();
        let name = &other.names()[choice];

        if let Some(part) = input.part_by_name_mut(name) {
            let size = part.bytes().len();
            let other_size = other.parts()[choice].bytes().len();

            if other_size < 2 {
                return Ok(MutationResult::Skipped);
            }
            drop(other_testcase);

            let target = state.rand_mut().below(size as u64) as usize;
            let range = rand_range(state, other_size, min(other_size, size - target));

            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // No need to load the input again, it'll still be cached.
            let other = other_testcase.input().as_ref().unwrap();

            Self::crossover_insert(part, size, target, range, &other.parts()[choice])
        } else {
            // just add it!
            input.add_part(name.clone(), other.parts()[choice].clone())?;

            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, S> Mutator<MultipartInput<I>, S> for CrossoverReplaceMutator<I>
where
    S: HasCorpus<Input = MultipartInput<I>> + HasMaxSize + HasRand,
    I: Input + HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I>,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        // we can eat the slight bias; number of parts will be small
        let next = state.rand_mut().next() as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;

        let choice = next % other.parts().len();
        let name = &other.names()[choice];

        if let Some(part) = input.part_by_name_mut(name) {
            let size = part.bytes().len();
            let other_size = other.parts()[choice].bytes().len();

            if other_size < 2 {
                return Ok(MutationResult::Skipped);
            }
            drop(other_testcase);

            let target = state.rand_mut().below(size as u64) as usize;
            let range = rand_range(state, other_size, min(other_size, size - target));

            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // No need to load the input again, it'll still be cached.
            let other = other_testcase.input().as_ref().unwrap();

            Self::crossover_replace(part, target, range, &other.parts()[choice])
        } else {
            // just add it!
            input.add_part(name.clone(), other.parts()[choice].clone())?;

            Ok(MutationResult::Mutated)
        }
    }
}
