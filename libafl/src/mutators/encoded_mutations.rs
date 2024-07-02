//! Mutations for [`EncodedInput`]s
//!
use alloc::{borrow::Cow, vec::Vec};
use core::cmp::{max, min};

use libafl_bolts::{
    rands::Rand,
    tuples::{tuple_list, tuple_list_type},
};

use crate::{
    corpus::Corpus,
    inputs::{EncodedInput, UsesInput},
    mutators::{
        mutations::{buffer_copy, buffer_self_copy, ARITH_MAX},
        MutationResult, Mutator, Named,
    },
    random_corpus_id_with_disabled,
    state::{HasCorpus, HasMaxSize, HasRand},
    Error,
};

/// Set a code in the input as a random value
#[derive(Debug, Default)]
pub struct EncodedRandMutator;

impl<S: HasRand> Mutator<EncodedInput, S> for EncodedRandMutator {
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        if input.codes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let val = state.rand_mut().choose(input.codes_mut()).unwrap();
            *val = state.rand_mut().next() as u32;
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for EncodedRandMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedRandMutator");
        &NAME
    }
}

impl EncodedRandMutator {
    /// Creates a new [`EncodedRandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Increment a random code in the input
#[derive(Debug, Default)]
pub struct EncodedIncMutator;

impl<S: HasRand> Mutator<EncodedInput, S> for EncodedIncMutator {
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        if input.codes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let val = state.rand_mut().choose(input.codes_mut()).unwrap();
            *val = val.wrapping_add(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for EncodedIncMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedIncMutator");
        &NAME
    }
}

impl EncodedIncMutator {
    /// Creates a new [`EncodedIncMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Decrement a random code in the input
#[derive(Debug, Default)]
pub struct EncodedDecMutator;

impl<S: HasRand> Mutator<EncodedInput, S> for EncodedDecMutator {
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        if input.codes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let val = state.rand_mut().choose(input.codes_mut()).unwrap();
            *val = val.wrapping_sub(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for EncodedDecMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedDecMutator");
        &NAME
    }
}

impl EncodedDecMutator {
    /// Creates a new [`EncodedDecMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Adds or subtracts a random value up to `ARITH_MAX` to a random place in the codes [`Vec`].
#[derive(Debug, Default)]
pub struct EncodedAddMutator;

impl<S: HasRand> Mutator<EncodedInput, S> for EncodedAddMutator {
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        if input.codes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let val = state.rand_mut().choose(input.codes_mut()).unwrap();
            let num = 1 + state.rand_mut().below(ARITH_MAX) as u32;
            *val = match state.rand_mut().below(2) {
                0 => val.wrapping_add(num),
                _ => val.wrapping_sub(num),
            };
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for EncodedAddMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedAddMutator");
        &NAME
    }
}

impl EncodedAddMutator {
    /// Creates a new [`EncodedAddMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Codes delete mutation for encoded inputs
#[derive(Debug, Default)]
pub struct EncodedDeleteMutator;

impl<S: HasRand> Mutator<EncodedInput, S> for EncodedDeleteMutator {
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        let size = input.codes().len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        let off = state.rand_mut().below(size);
        let len = state.rand_mut().below(size - off);
        input.codes_mut().drain(off..off + len);

        Ok(MutationResult::Mutated)
    }
}

impl Named for EncodedDeleteMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedDeleteMutator");
        &NAME
    }
}

impl EncodedDeleteMutator {
    /// Creates a new [`EncodedDeleteMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Insert mutation for encoded inputs
#[derive(Debug, Default)]
pub struct EncodedInsertCopyMutator {
    tmp_buf: Vec<u32>,
}

impl<S> Mutator<EncodedInput, S> for EncodedInsertCopyMutator
where
    S: HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.codes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }
        let off = state.rand_mut().below(size + 1);
        let mut len = 1 + state.rand_mut().below(min(16, size));

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        let from = if size == len {
            0
        } else {
            state.rand_mut().below(size - len)
        };

        input.codes_mut().resize(size + len, 0);
        self.tmp_buf.resize(len, 0);
        unsafe {
            buffer_copy(&mut self.tmp_buf, input.codes(), from, 0, len);

            buffer_self_copy(input.codes_mut(), off, off + len, size - off);
            buffer_copy(input.codes_mut(), &self.tmp_buf, 0, off, len);
        };

        Ok(MutationResult::Mutated)
    }
}

impl Named for EncodedInsertCopyMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedInsertCopyMutator");
        &NAME
    }
}

impl EncodedInsertCopyMutator {
    /// Creates a new [`EncodedInsertCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Codes copy mutation for encoded inputs
#[derive(Debug, Default)]
pub struct EncodedCopyMutator;

impl<S: HasRand> Mutator<EncodedInput, S> for EncodedCopyMutator {
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        let size = input.codes().len();
        if size <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(size);
        let to = state.rand_mut().below(size);
        let len = 1 + state.rand_mut().below(size - max(from, to));

        unsafe {
            buffer_self_copy(input.codes_mut(), from, to, len);
        }

        Ok(MutationResult::Mutated)
    }
}

impl Named for EncodedCopyMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedCopyMutator");
        &NAME
    }
}

impl EncodedCopyMutator {
    /// Creates a new [`EncodedCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Crossover insert mutation for encoded inputs
#[derive(Debug, Default)]
pub struct EncodedCrossoverInsertMutator;

impl<S> Mutator<S::Input, S> for EncodedCrossoverInsertMutator
where
    S: UsesInput<Input = EncodedInput> + HasRand + HasCorpus + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        let size = input.codes().len();

        let id = random_corpus_id_with_disabled!(state.corpus(), state.rand_mut());
        // We don't want to use the testcase we're already using for splicing
        if let Some(cur) = state.corpus().current() {
            if id == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_size = {
            let mut other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
            other_testcase.load_input(state.corpus())?.codes().len()
        };

        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let max_size = state.max_size();
        let from = state.rand_mut().below(other_size);
        let to = state.rand_mut().below(size);
        let mut len = 1 + state.rand_mut().below(other_size - from);

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
        // no need to `load_input` again -  we did that above already.
        let other = other_testcase.input().as_ref().unwrap();

        input.codes_mut().resize(size + len, 0);
        unsafe {
            buffer_self_copy(input.codes_mut(), to, to + len, size - to);
            buffer_copy(input.codes_mut(), other.codes(), from, to, len);
        }

        Ok(MutationResult::Mutated)
    }
}

impl Named for EncodedCrossoverInsertMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedCrossoverInsertMutator");
        &NAME
    }
}

impl EncodedCrossoverInsertMutator {
    /// Creates a new [`EncodedCrossoverInsertMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Crossover replace mutation for encoded inputs
#[derive(Debug, Default)]
pub struct EncodedCrossoverReplaceMutator;

impl<S> Mutator<S::Input, S> for EncodedCrossoverReplaceMutator
where
    S: UsesInput<Input = EncodedInput> + HasRand + HasCorpus,
{
    fn mutate(&mut self, state: &mut S, input: &mut EncodedInput) -> Result<MutationResult, Error> {
        let size = input.codes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }

        let id = random_corpus_id_with_disabled!(state.corpus(), state.rand_mut());
        // We don't want to use the testcase we're already using for splicing
        if let Some(cur) = state.corpus().current() {
            if id == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_size = {
            // new scope to make the borrow checker happy
            let mut other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
            other_testcase.load_input(state.corpus())?.codes().len()
        };

        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(other_size);
        let len = state.rand_mut().below(min(other_size - from, size));
        let to = state.rand_mut().below(size - len);

        let other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
        // no need to load the input again, it'll already be present at this point.
        let other = other_testcase.input().as_ref().unwrap();

        unsafe {
            buffer_copy(input.codes_mut(), other.codes(), from, to, len);
        }

        Ok(MutationResult::Mutated)
    }
}

impl Named for EncodedCrossoverReplaceMutator {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("EncodedCrossoverReplaceMutator");
        &NAME
    }
}

impl EncodedCrossoverReplaceMutator {
    /// Creates a new [`EncodedCrossoverReplaceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Get the mutations that compose the encoded mutator
#[must_use]
pub fn encoded_mutations() -> tuple_list_type!(
    EncodedRandMutator,
    EncodedIncMutator,
    EncodedDecMutator,
    EncodedAddMutator,
    EncodedDeleteMutator,
    EncodedInsertCopyMutator,
    EncodedCopyMutator,
    EncodedCrossoverInsertMutator,
    EncodedCrossoverReplaceMutator,
) {
    tuple_list!(
        EncodedRandMutator::new(),
        EncodedIncMutator::new(),
        EncodedDecMutator::new(),
        EncodedAddMutator::new(),
        EncodedDeleteMutator::new(),
        EncodedInsertCopyMutator::new(),
        EncodedCopyMutator::new(),
        EncodedCrossoverInsertMutator::new(),
        EncodedCrossoverReplaceMutator::new(),
    )
}
