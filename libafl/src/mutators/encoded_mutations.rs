use alloc::vec::Vec;
use core::{
    cmp::{max, min},
    marker::PhantomData,
};

use crate::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, tuple_list_type},
    },
    corpus::Corpus,
    inputs::EncodedInput,
    mutators::{
        mutations::{buffer_copy, buffer_self_copy, ARITH_MAX},
        MutationResult, Mutator, Named,
    },
    state::{HasCorpus, HasMaxSize, HasRand},
    Error,
};

/// Set a code in the input as a random value
#[derive(Default)]
pub struct EncodedRandMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<EncodedInput, S> for EncodedRandMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.codes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let val = state.rand_mut().choose(input.codes_mut());
            *val = state.rand_mut().next() as u32;
            Ok(MutationResult::Mutated)
        }
    }
}

impl<R, S> Named for EncodedRandMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "EncodedRandMutator"
    }
}

impl<R, S> EncodedRandMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`EncodedRandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Increment a random code in the input
#[derive(Default)]
pub struct EncodedIncMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<EncodedInput, S> for EncodedIncMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.codes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let val = state.rand_mut().choose(input.codes_mut());
            *val = val.wrapping_add(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl<R, S> Named for EncodedIncMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "EncodedIncMutator"
    }
}

impl<R, S> EncodedIncMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`EncodedRandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Decrement a random code in the input
#[derive(Default)]
pub struct EncodedDecMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<EncodedInput, S> for EncodedDecMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.codes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let val = state.rand_mut().choose(input.codes_mut());
            *val = val.wrapping_sub(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl<R, S> Named for EncodedDecMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "EncodedDecMutator"
    }
}

impl<R, S> EncodedDecMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`EncodedRandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Adds or subtracts a random value up to `ARITH_MAX` to a random place in the codes [`Vec`].
#[derive(Default)]
pub struct EncodedAddMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<EncodedInput, S> for EncodedAddMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.codes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let val = state.rand_mut().choose(input.codes_mut());
            let num = 1 + state.rand_mut().below(ARITH_MAX) as u32;
            *val = match state.rand_mut().below(2) {
                0 => val.wrapping_add(num),
                _ => val.wrapping_sub(num),
            };
            Ok(MutationResult::Mutated)
        }
    }
}

impl<R, S> Named for EncodedAddMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "EncodedAddMutator"
    }
}

impl<R, S> EncodedAddMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`EncodedAddMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Codes delete mutation for encoded inputs
#[derive(Default)]
pub struct EncodedDeleteMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<EncodedInput, S> for EncodedDeleteMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.codes().len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        let off = state.rand_mut().below(size as u64) as usize;
        let len = state.rand_mut().below((size - off) as u64) as usize;
        input.codes_mut().drain(off..off + len);

        Ok(MutationResult::Mutated)
    }
}

impl<R, S> Named for EncodedDeleteMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "EncodedDeleteMutator"
    }
}

impl<R, S> EncodedDeleteMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`EncodedDeleteMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Insert mutation for encoded inputs
#[derive(Default)]
pub struct EncodedInsertCopyMutator<R, S>
where
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    tmp_buf: Vec<u32>,
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<EncodedInput, S> for EncodedInsertCopyMutator<R, S>
where
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.codes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }
        let off = state.rand_mut().below((size + 1) as u64) as usize;
        let mut len = 1 + state.rand_mut().below(min(16, size as u64)) as usize;

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
            state.rand_mut().below((size - len) as u64) as usize
        };

        input.codes_mut().resize(size + len, 0);
        self.tmp_buf.resize(len, 0);
        buffer_copy(&mut self.tmp_buf, input.codes(), from, 0, len);

        buffer_self_copy(input.codes_mut(), off, off + len, size - off);
        buffer_copy(input.codes_mut(), &self.tmp_buf, 0, off, len);

        Ok(MutationResult::Mutated)
    }
}

impl<R, S> Named for EncodedInsertCopyMutator<R, S>
where
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn name(&self) -> &str {
        "EncodedInsertCopyMutator"
    }
}

impl<R, S> EncodedInsertCopyMutator<R, S>
where
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    /// Creates a new [`EncodedInsertCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            tmp_buf: vec![],
            phantom: PhantomData,
        }
    }
}

/// Codes copy mutation for encoded inputs
#[derive(Default)]
pub struct EncodedCopyMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(R, S)>,
}

impl<R, S> Mutator<EncodedInput, S> for EncodedCopyMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.codes().len();
        if size <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(size as u64) as usize;
        let to = state.rand_mut().below(size as u64) as usize;
        let len = 1 + state.rand_mut().below((size - max(from, to)) as u64) as usize;

        buffer_self_copy(input.codes_mut(), from, to, len);

        Ok(MutationResult::Mutated)
    }
}

impl<R, S> Named for EncodedCopyMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "EncodedCopyMutator"
    }
}

impl<R, S> EncodedCopyMutator<R, S>
where
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`EncodedCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Crossover insert mutation for encoded inputs
#[derive(Default)]
pub struct EncodedCrossoverInsertMutator<C, R, S>
where
    C: Corpus<EncodedInput>,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, EncodedInput> + HasMaxSize,
{
    phantom: PhantomData<(C, R, S)>,
}

impl<C, R, S> Mutator<EncodedInput, S> for EncodedCrossoverInsertMutator<C, R, S>
where
    C: Corpus<EncodedInput>,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, EncodedInput> + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.codes().len();

        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_size = state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .load_input()?
            .codes()
            .len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let max_size = state.max_size();
        let from = state.rand_mut().below(other_size as u64) as usize;
        let to = state.rand_mut().below(size as u64) as usize;
        let mut len = 1 + state.rand_mut().below((other_size - from) as u64) as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input()?;

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        input.codes_mut().resize(size + len, 0);
        buffer_self_copy(input.codes_mut(), to, to + len, size - to);
        buffer_copy(input.codes_mut(), other.codes(), from, to, len);

        Ok(MutationResult::Mutated)
    }
}

impl<C, R, S> Named for EncodedCrossoverInsertMutator<C, R, S>
where
    C: Corpus<EncodedInput>,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, EncodedInput> + HasMaxSize,
{
    fn name(&self) -> &str {
        "EncodedCrossoverInsertMutator"
    }
}

impl<C, R, S> EncodedCrossoverInsertMutator<C, R, S>
where
    C: Corpus<EncodedInput>,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, EncodedInput> + HasMaxSize,
{
    /// Creates a new [`EncodedCrossoverInsertMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Crossover replace mutation for encoded inputs
#[derive(Default)]
pub struct EncodedCrossoverReplaceMutator<C, R, S>
where
    C: Corpus<EncodedInput>,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, EncodedInput>,
{
    phantom: PhantomData<(C, R, S)>,
}

impl<C, R, S> Mutator<EncodedInput, S> for EncodedCrossoverReplaceMutator<C, R, S>
where
    C: Corpus<EncodedInput>,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, EncodedInput>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut EncodedInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.codes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }

        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_size = state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .load_input()?
            .codes()
            .len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(other_size as u64) as usize;
        let len = state.rand_mut().below(min(other_size - from, size) as u64) as usize;
        let to = state.rand_mut().below((size - len) as u64) as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input()?;

        buffer_copy(input.codes_mut(), other.codes(), from, to, len);

        Ok(MutationResult::Mutated)
    }
}

impl<C, R, S> Named for EncodedCrossoverReplaceMutator<C, R, S>
where
    C: Corpus<EncodedInput>,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, EncodedInput>,
{
    fn name(&self) -> &str {
        "EncodedCrossoverReplaceMutator"
    }
}

impl<C, R, S> EncodedCrossoverReplaceMutator<C, R, S>
where
    C: Corpus<EncodedInput>,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, EncodedInput>,
{
    /// Creates a new [`EncodedCrossoverReplaceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Get the mutations that compose the encoded mutator
#[must_use]
pub fn encoded_mutations<C, R, S>() -> tuple_list_type!(
       EncodedRandMutator<R, S>,
       EncodedIncMutator<R, S>,
       EncodedDecMutator<R, S>,
       EncodedAddMutator<R, S>,
       EncodedDeleteMutator<R, S>,
       EncodedInsertCopyMutator<R, S>,
       EncodedCopyMutator<R, S>,
       EncodedCrossoverInsertMutator<C, R, S>,
       EncodedCrossoverReplaceMutator<C, R, S>,
   )
where
    S: HasRand<R> + HasCorpus<C, EncodedInput> + HasMaxSize,
    C: Corpus<EncodedInput>,
    R: Rand,
{
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
