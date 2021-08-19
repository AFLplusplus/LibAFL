use core::marker::PhantomData;

use crate::{
    bolts::rands::Rand,
    inputs::EncodedInput,
    mutators::{
        buffer_self_copy,
        mutations::{buffer_copy, ARITH_MAX},
        MutationResult, Mutator, Named,
    },
    state::{HasMaxSize, HasRand},
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
