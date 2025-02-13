//! Mutator definitions for [`MultipartInput`]s. See [`crate::inputs::multi`] for details.

use alloc::borrow::Cow;
use core::{
    cmp::{min, Ordering},
    num::NonZero,
};

use libafl_bolts::{rands::Rand, Error, Named};

use crate::{
    corpus::{Corpus, CorpusId},
    generators::Generator,
    impl_default_multipart,
    inputs::{multi::MultipartInput, HasMutatorBytes, Input, ResizableMutator},
    mutators::{
        mutations::{
            rand_range, BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator,
            ByteIncMutator, ByteInterestingMutator, ByteNegMutator, ByteRandMutator,
            BytesCopyMutator, BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator,
            BytesInsertMutator, BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator,
            BytesSwapMutator, CrossoverInsertMutator as BytesInputCrossoverInsertMutator,
            CrossoverReplaceMutator as BytesInputCrossoverReplaceMutator, DwordAddMutator,
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

impl<I, M, N, S> Mutator<MultipartInput<I, N>, S> for M
where
    M: DefaultMultipartMutator + Mutator<I, S>,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        let Some(parts_len) = NonZero::new(input.len()) else {
            return Ok(MutationResult::Skipped);
        };
        let selected = state.rand_mut().below(parts_len);
        let mutated = input.part_by_idx_mut(selected).unwrap();
        self.mutate(state, mutated)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        M::post_exec(self, state, new_corpus_id)
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

impl<I, N, S> Mutator<MultipartInput<I, N>, S> for BytesInputCrossoverInsertMutator
where
    S: HasCorpus<MultipartInput<I, N>> + HasMaxSize + HasRand,
    I: Input + ResizableMutator<u8> + HasMutatorBytes,
    N: Clone + PartialEq,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        // we can eat the slight bias; number of parts will be small
        let name_choice = state.rand_mut().next() as usize;
        let part_choice = state.rand_mut().next() as usize;

        // We special-case crossover with self
        let id = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if id == *cur {
                let len = input.len();
                if len == 0 {
                    return Ok(MutationResult::Skipped);
                }
                let choice = name_choice % len;
                let name = input.names().nth(choice).unwrap();

                let other_size = input.part_by_idx(choice).unwrap().mutator_bytes().len();
                if other_size < 2 {
                    return Ok(MutationResult::Skipped);
                }

                let parts = input.parts_with_name(name).count() - 1;

                if parts == 0 {
                    return Ok(MutationResult::Skipped);
                }

                let maybe_size = input
                    .parts_with_name(name)
                    .filter(|&(p, _)| p != choice)
                    .nth(part_choice % parts)
                    .map(|(id, part)| (id, part.mutator_bytes().len()));

                if let Some((part_idx, size)) = maybe_size {
                    let Some(nz) = NonZero::new(size) else {
                        return Ok(MutationResult::Skipped);
                    };
                    let target = state.rand_mut().below(nz);
                    // # Safety
                    // size is nonzero here (checked above), target is smaller than size
                    // -> the subtraction result is greater than 0.
                    // other_size is checked above to be larger than zero.
                    let range = rand_range(state, other_size, unsafe {
                        NonZero::new(min(other_size, size - target)).unwrap_unchecked()
                    });

                    let [part, chosen] = match part_idx.cmp(&choice) {
                        Ordering::Less => input.parts_by_idxs_mut([part_idx, choice]),
                        Ordering::Equal => {
                            unreachable!("choice should never equal the part idx!")
                        }
                        Ordering::Greater => {
                            let [chosen, part] = input.parts_by_idxs_mut([choice, part_idx]);
                            [part, chosen]
                        }
                    };

                    return Ok(Self::crossover_insert(
                        part,
                        size,
                        target,
                        range,
                        chosen.mutator_bytes(),
                    ));
                }

                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get(id)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;
        let other_len = other.len();
        if other_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        let choice = name_choice % other_len;
        let name = other.names().nth(choice).unwrap();

        let other_size = other.part_by_idx(choice).unwrap().mutator_bytes().len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let parts = input.parts_with_name(name).count();

        if parts > 0 {
            let (_, part) = input
                .parts_with_name_mut(name)
                .nth(part_choice % parts)
                .unwrap();
            drop(other_testcase);
            let size = part.mutator_bytes().len();
            let Some(nz) = NonZero::new(size) else {
                return Ok(MutationResult::Skipped);
            };

            let target = state.rand_mut().below(nz);
            // # Safety
            // other_size is larger than 0, checked above.
            // size is larger than 0.
            // target is smaller than size -> the subtraction is larger than 0.
            let range = rand_range(state, other_size, unsafe {
                NonZero::new(min(other_size, size - target)).unwrap_unchecked()
            });

            let other_testcase = state.corpus().get(id)?.borrow_mut();
            // No need to load the input again, it'll still be cached.
            let other = other_testcase.input().as_ref().unwrap();

            Ok(Self::crossover_insert(
                part,
                size,
                target,
                range,
                other.part_by_idx(choice).unwrap().mutator_bytes(),
            ))
        } else {
            // just add it!
            input.append_part(name.clone(), other.part_by_idx(choice).unwrap().clone());

            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, N, S> Mutator<MultipartInput<I, N>, S> for BytesInputCrossoverReplaceMutator
where
    S: HasCorpus<MultipartInput<I, N>> + HasMaxSize + HasRand,
    I: Input + ResizableMutator<u8> + HasMutatorBytes,
    N: Clone + PartialEq,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        // we can eat the slight bias; number of parts will be small
        let name_choice = state.rand_mut().next() as usize;
        let part_choice = state.rand_mut().next() as usize;

        // We special-case crossover with self
        let id = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if id == *cur {
                let len = input.iter().count();
                if len == 0 {
                    return Ok(MutationResult::Skipped);
                }
                let choice = name_choice % len;
                let name = input.names().nth(choice).unwrap();

                let other_size = input.part_by_idx(choice).unwrap().mutator_bytes().len();
                if other_size < 2 {
                    return Ok(MutationResult::Skipped);
                }

                let parts = input.parts_with_name(name).count() - 1;

                if parts == 0 {
                    return Ok(MutationResult::Skipped);
                }

                let maybe_size = input
                    .parts_with_name(name)
                    .filter(|&(p, _)| p != choice)
                    .nth(part_choice % parts)
                    .map(|(id, part)| (id, part.mutator_bytes().len()));

                if let Some((part_idx, size)) = maybe_size {
                    let Some(nz) = NonZero::new(size) else {
                        return Ok(MutationResult::Skipped);
                    };

                    let target = state.rand_mut().below(nz);
                    // # Safety
                    // other_size is checked above.
                    // size is larger than than target and larger than 1. The subtraction result will always be positive.
                    let range = rand_range(state, other_size, unsafe {
                        NonZero::new(min(other_size, size - target)).unwrap_unchecked()
                    });

                    let [part, chosen] = match part_idx.cmp(&choice) {
                        Ordering::Less => input.parts_by_idxs_mut([part_idx, choice]),
                        Ordering::Equal => {
                            unreachable!("choice should never equal the part idx!")
                        }
                        Ordering::Greater => {
                            let [chosen, part] = input.parts_by_idxs_mut([choice, part_idx]);
                            [part, chosen]
                        }
                    };

                    return Ok(Self::crossover_replace(
                        part,
                        target,
                        range,
                        chosen.mutator_bytes(),
                    ));
                }

                return Ok(MutationResult::Skipped);
            }
        }

        let mut other_testcase = state.corpus().get(id)?.borrow_mut();
        let other = other_testcase.load_input(state.corpus())?;

        let other_len = other.iter().count();
        if other_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        let choice = name_choice % other_len;
        let name = other.names().nth(choice).unwrap();

        let other_size = other.part_by_idx(choice).unwrap().mutator_bytes().len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let parts = input.parts_with_name(name).count();

        if parts > 0 {
            let (_, part) = input
                .parts_with_name_mut(name)
                .nth(part_choice % parts)
                .unwrap();
            drop(other_testcase);
            let size = part.mutator_bytes().len();
            let Some(nz) = NonZero::new(size) else {
                return Ok(MutationResult::Skipped);
            };

            let target = state.rand_mut().below(nz);
            // # Safety
            // other_size is checked above.
            // size is larger than than target and larger than 1. The subtraction result will always be positive.
            let range = rand_range(state, other_size, unsafe {
                NonZero::new(min(other_size, size - target)).unwrap_unchecked()
            });

            let other_testcase = state.corpus().get(id)?.borrow_mut();
            // No need to load the input again, it'll still be cached.
            let other = other_testcase.input().as_ref().unwrap();

            Ok(Self::crossover_replace(
                part,
                target,
                range,
                other.part_by_idx(choice).unwrap().mutator_bytes(),
            ))
        } else {
            // just add it!
            input.append_part(name.clone(), other.part_by_idx(choice).unwrap().clone());

            Ok(MutationResult::Mutated)
        }
    }
}

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

impl<G, I, N, S> Mutator<MultipartInput<I, N>, S> for GenerateToAppendMutator<G>
where
    G: Generator<I, S>,
    N: Default,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        let generated = self.generator.generate(state)?;
        input.append_part_with_default_name(generated);
        Ok(MutationResult::Mutated)
    }
}

impl<G> Named for GenerateToAppendMutator<G> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("GenerateToAppendMutator")
    }
}

/// Mutator that removes the last entry from a [`MultipartInput`].
///
/// Returns [`MutationResult::Skipped`] if the input is empty.
#[derive(Debug)]
pub struct RemoveLastEntryMutator;

impl<I, N, S> Mutator<MultipartInput<I, N>, S> for RemoveLastEntryMutator
where
    N: Default,
{
    fn mutate(
        &mut self,
        _state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        match input.pop_part() {
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

/// Mutator that removes a random entry from a [`MultipartInput`].
///
/// Returns [`MutationResult::Skipped`] if the input is empty.
#[derive(Debug)]
pub struct RemoveRandomEntryMutator;

impl<I, N, S> Mutator<MultipartInput<I, N>, S> for RemoveRandomEntryMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        match MultipartInput::len(input) {
            0 => Ok(MutationResult::Skipped),
            len => {
                // Safety: null checks are done above
                let index = state
                    .rand_mut()
                    .below(unsafe { NonZero::new_unchecked(len) });
                input.remove_part_at_idx(index);
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

/// Mutator that inserts a random part from another [`MultipartInput`] into the current input.
#[derive(Debug)]
pub struct CrossoverInsertMutator;

impl<I, N, S> Mutator<MultipartInput<I, N>, S> for CrossoverInsertMutator
where
    S: HasCorpus<MultipartInput<I, N>> + HasMaxSize + HasRand,
    I: Clone,
    N: Clone,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        let current_idx = match input.len() {
            0 => return Ok(MutationResult::Skipped),
            len => state
                .rand_mut()
                .below(unsafe { NonZero::new_unchecked(len) }),
        };
        let other_idx_raw = state.rand_mut().next() as usize;

        let id = random_corpus_id!(state.corpus(), state.rand_mut());
        let mut testcase = state.corpus().get(id)?.borrow_mut();
        let other = testcase.load_input(state.corpus())?;

        let other_len = other.len();

        let (name, part) = match other_len {
            0 => return Ok(MutationResult::Skipped),
            len => other.parts_and_names()[other_idx_raw % len].clone(),
        };

        input.insert_part(current_idx, name, part);
        Ok(MutationResult::Mutated)
    }
}

impl Named for CrossoverInsertMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("CrossoverInsertMutator")
    }
}

/// Mutator that replaces a random part from the current [`MultipartInput`] with a random part from another input.
#[derive(Debug)]
pub struct CrossoverReplaceMutator;

impl<I, N, S> Mutator<MultipartInput<I, N>, S> for CrossoverReplaceMutator
where
    S: HasCorpus<MultipartInput<I, N>> + HasMaxSize + HasRand,
    I: Clone,
    N: Clone,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut MultipartInput<I, N>,
    ) -> Result<MutationResult, Error> {
        let current_idx = match input.len() {
            0 => return Ok(MutationResult::Skipped),
            len => state
                .rand_mut()
                .below(unsafe { NonZero::new_unchecked(len) }),
        };
        let other_idx_raw = state.rand_mut().next() as usize;

        let id = random_corpus_id!(state.corpus(), state.rand_mut());
        let mut testcase = state.corpus().get(id)?.borrow_mut();
        let other = testcase.load_input(state.corpus())?;

        let other_len = other.len();

        let (name, part) = match other_len {
            0 => return Ok(MutationResult::Skipped),
            len => other.parts_and_names()[other_idx_raw % len].clone(),
        };

        input.remove_part_at_idx(current_idx);
        input.insert_part(current_idx, name, part);
        Ok(MutationResult::Mutated)
    }
}

impl Named for CrossoverReplaceMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("CrossoverReplaceMutator")
    }
}
