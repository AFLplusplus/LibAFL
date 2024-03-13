//! Mutator definitions for [`MultipartInput`]s. See [`crate::inputs::multi`] for details.

use core::cmp::{min, Ordering};

use libafl_bolts::{rands::Rand, Error};

use crate::{
    corpus::{Corpus, CorpusId},
    impl_default_multipart,
    inputs::{multi::MultipartInput, HasBytesVec, Input},
    mutators::{
        mutations::{
            rand_range, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator,
            ByteIncMutator, ByteInterestingMutator, ByteNegMutator, ByteRandMutator,
            BytesCopyMutator, BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator,
            BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
            BytesSwapMutator, CrossoverInsertMutator, CrossoverReplaceMutator, DwordAddMutator,
            DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
        },
        token_mutations::{I2SRandReplace, TokenInsert, TokenReplace},
        MutationResult, Mutator,
    },
    random_corpus_id,
    state::{HasCorpus, HasMaxSize, HasRand},
};

/// Marker trait for if the default multipart input mutator implementation is appropriate.
///
/// You should implement this type for your mutator if you just want a random part of the input to
/// be selected and mutated. Use [`impl_default_multipart`] to implement this marker trait for many
/// at once.
pub trait DefaultMultipartMutator {}

impl<I, M, S> Mutator<MultipartInput<I>, S> for M
where
    M: DefaultMultipartMutator + Mutator<I, S>,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I>,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.parts().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let selected = state.rand_mut().below(input.parts().len() as u64) as usize;
            let mutated = input.part_mut(selected).unwrap();
            self.mutate(state, mutated, stage_idx)
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        stage_idx: i32,
        new_corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        M::post_exec(self, state, stage_idx, new_corpus_idx)
    }
}

mod macros {
    /// Implements the marker trait [`super::DefaultMultipartMutator`] for one to many types, e.g.:
    ///
    /// ```rs
    /// impl_default_multipart!(
    ///     // --- havoc ---
    ///     BitFlipMutator,
    ///     ByteAddMutator,
    ///     ByteDecMutator,
    ///     ByteFlipMutator,
    ///     ByteIncMutator,
    ///     ...
    /// );
    /// ```
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
        // we can eat the slight bias; number of parts will be small
        let name_choice = state.rand_mut().next() as usize;
        let part_choice = state.rand_mut().next() as usize;

        // We special-case crossover with self
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                let choice = name_choice % input.names().len();
                let name = input.names()[choice].clone();

                let other_size = input.parts()[choice].bytes().len();
                if other_size < 2 {
                    return Ok(MutationResult::Skipped);
                }

                let parts = input.parts_by_name(&name).count() - 1;

                if parts == 0 {
                    return Ok(MutationResult::Skipped);
                }

                let maybe_size = input
                    .parts_by_name(&name)
                    .filter(|&(p, _)| p != choice)
                    .nth(part_choice % parts)
                    .map(|(idx, part)| (idx, part.bytes().len()));

                if let Some((part_idx, size)) = maybe_size {
                    let target = state.rand_mut().below(size as u64) as usize;
                    let range = rand_range(state, other_size, min(other_size, size - target));

                    let [part, chosen] = match part_idx.cmp(&choice) {
                        Ordering::Less => input.parts_mut([part_idx, choice]),
                        Ordering::Equal => {
                            unreachable!("choice should never equal the part idx!")
                        }
                        Ordering::Greater => {
                            let [chosen, part] = input.parts_mut([choice, part_idx]);
                            [part, chosen]
                        }
                    };

                    return Ok(Self::crossover_insert(part, size, target, range, chosen));
                }

                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;

        let choice = name_choice % other.names().len();
        let name = &other.names()[choice];

        let other_size = other.parts()[choice].bytes().len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let parts = input.parts_by_name(name).count();

        if parts > 0 {
            let (_, part) = input
                .parts_by_name_mut(name)
                .nth(part_choice % parts)
                .unwrap();
            drop(other_testcase);
            let size = part.bytes().len();

            let target = state.rand_mut().below(size as u64) as usize;
            let range = rand_range(state, other_size, min(other_size, size - target));

            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // No need to load the input again, it'll still be cached.
            let other = other_testcase.input().as_ref().unwrap();

            Ok(Self::crossover_insert(
                part,
                size,
                target,
                range,
                &other.parts()[choice],
            ))
        } else {
            // just add it!
            input.add_part(name.clone(), other.parts()[choice].clone());

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
        // we can eat the slight bias; number of parts will be small
        let name_choice = state.rand_mut().next() as usize;
        let part_choice = state.rand_mut().next() as usize;

        // We special-case crossover with self
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                let choice = name_choice % input.names().len();
                let name = input.names()[choice].clone();

                let other_size = input.parts()[choice].bytes().len();
                if other_size < 2 {
                    return Ok(MutationResult::Skipped);
                }

                let parts = input.parts_by_name(&name).count() - 1;

                if parts == 0 {
                    return Ok(MutationResult::Skipped);
                }

                let maybe_size = input
                    .parts_by_name(&name)
                    .filter(|&(p, _)| p != choice)
                    .nth(part_choice % parts)
                    .map(|(idx, part)| (idx, part.bytes().len()));

                if let Some((part_idx, size)) = maybe_size {
                    let target = state.rand_mut().below(size as u64) as usize;
                    let range = rand_range(state, other_size, min(other_size, size - target));

                    let [part, chosen] = match part_idx.cmp(&choice) {
                        Ordering::Less => input.parts_mut([part_idx, choice]),
                        Ordering::Equal => {
                            unreachable!("choice should never equal the part idx!")
                        }
                        Ordering::Greater => {
                            let [chosen, part] = input.parts_mut([choice, part_idx]);
                            [part, chosen]
                        }
                    };

                    return Ok(Self::crossover_replace(part, target, range, chosen));
                }

                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;

        let choice = name_choice % other.names().len();
        let name = &other.names()[choice];

        let other_size = other.parts()[choice].bytes().len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let parts = input.parts_by_name(name).count();

        if parts > 0 {
            let (_, part) = input
                .parts_by_name_mut(name)
                .nth(part_choice % parts)
                .unwrap();
            drop(other_testcase);
            let size = part.bytes().len();

            let target = state.rand_mut().below(size as u64) as usize;
            let range = rand_range(state, other_size, min(other_size, size - target));

            let other_testcase = state.corpus().get(idx)?.borrow_mut();
            // No need to load the input again, it'll still be cached.
            let other = other_testcase.input().as_ref().unwrap();

            Ok(Self::crossover_replace(
                part,
                target,
                range,
                &other.parts()[choice],
            ))
        } else {
            // just add it!
            input.add_part(name.clone(), other.parts()[choice].clone());

            Ok(MutationResult::Mutated)
        }
    }
}
