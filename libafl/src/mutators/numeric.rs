//! Mutators for integer-style inputs

use alloc::borrow::Cow;
use core::ops::{BitOrAssign, BitXorAssign, Not, Shl};

use libafl_bolts::{rands::Rand as _, Error, Named};
use num_traits::{One, WrappingAdd, WrappingSub, Zero};
use tuple_list::{tuple_list, tuple_list_type};

use super::{MutationResult, Mutator};
use crate::{
    corpus::Corpus,
    inputs::ValueInput,
    random_corpus_id_with_disabled,
    state::{HasCorpus, HasRand},
};

/// All mutators for integer-like inputs, return type of [`int_mutators`]
pub type IntMutatorsType = tuple_list_type!(
    BitFlipMutator,
    FlipMutator,
    IncMutator,
    DecMutator,
    NegMutator,
    RandMutator,
    CrossoverMutator
);

/// Mutators for integer-like inputs
///
/// Modelled after the applicable mutators from [`super::havoc_mutations::havoc_mutations`]
#[must_use]
pub fn int_mutators() -> IntMutatorsType {
    tuple_list!(
        BitFlipMutator,
        FlipMutator,
        IncMutator,
        DecMutator,
        NegMutator,
        RandMutator,
        CrossoverMutator
    )
}

/// Bitflip mutation for integer-like inputs
#[derive(Debug)]
pub struct BitFlipMutator;

impl<I, S> Mutator<I, S> for BitFlipMutator
where
    S: HasRand,
    I: Shl<usize, Output = I> + BitXorAssign + One,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        *input ^= I::one() << state.rand_mut().choose(0..size_of::<I>()).unwrap();
        Ok(MutationResult::Mutated)
    }
}

impl Named for BitFlipMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("BitFlipMutator")
    }
}

/// Flip mutation for integer-like inputs
#[derive(Debug)]
pub struct FlipMutator;

impl<I, S> Mutator<I, S> for FlipMutator
where
    I: Not<Output = I> + Copy,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        *input = !*input;
        Ok(MutationResult::Mutated)
    }
}

impl Named for FlipMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ByteFlipMutator")
    }
}

/// Increment mutation for integer-like inputs
#[derive(Debug)]
pub struct IncMutator;

impl<I, S> Mutator<I, S> for IncMutator
where
    I: WrappingAdd + One,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        *input = input.wrapping_add(&I::one());
        Ok(MutationResult::Mutated)
    }
}

impl Named for IncMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("IncMutator")
    }
}

/// Decrement mutation for integer-like inputs
#[derive(Debug)]
pub struct DecMutator;

impl<I, S> Mutator<I, S> for DecMutator
where
    I: WrappingSub + One,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        *input = input.wrapping_sub(&I::one());
        Ok(MutationResult::Mutated)
    }
}

impl Named for DecMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("DecMutator")
    }
}

/// Negate mutation for integer-like inputs
#[derive(Debug)]
pub struct NegMutator;

impl<I, S> Mutator<I, S> for NegMutator
where
    I: Not<Output = I> + WrappingAdd + One + Copy,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        *input = (!(*input)).wrapping_add(&I::one());
        Ok(MutationResult::Mutated)
    }
}

impl Named for NegMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("NegMutator")
    }
}

/// Randomize mutation for integer-like inputs
#[derive(Debug)]
pub struct RandMutator;

impl<I, S> Mutator<ValueInput<I>, S> for RandMutator
where
    S: HasRand,
    ValueInput<I>: Shl<usize, Output = ValueInput<I>> + BitOrAssign,
    I: From<u8> + Zero,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut ValueInput<I>,
    ) -> Result<MutationResult, Error> {
        // set to random data byte-wise since the RNGs don't work for all numeric types
        *input = I::zero().into();

        for offset in 0..(size_of::<I>() % size_of::<u8>()) {
            let raw = state.rand_mut().next() as u8;
            let inner: I = raw.into();
            let mask: ValueInput<I> = inner.into();
            *input |= mask << offset;
        }
        Ok(MutationResult::Mutated)
    }
}

impl Named for RandMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("RandMutator")
    }
}

/// Crossover mutation for integer-like inputs
#[derive(Debug)]
pub struct CrossoverMutator;

impl<I, S> Mutator<I, S> for CrossoverMutator
where
    S: HasRand + HasCorpus,
    S::Corpus: Corpus<Input = I>,
    I: Copy,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let id = random_corpus_id_with_disabled!(state.corpus(), state.rand_mut());

        if state.corpus().current().is_some_and(|cur| cur == id) {
            return Ok(MutationResult::Skipped);
        }

        let other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
        *input = *other_testcase.input().as_ref().unwrap();
        Ok(MutationResult::Mutated)
    }
}

impl Named for CrossoverMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("CrossoverMutator")
    }
}

#[cfg(test)]
mod tests {
    use libafl_bolts::{rands::StdRand, tuples::IntoVec as _};

    use super::int_mutators;
    use crate::{
        corpus::{Corpus as _, InMemoryCorpus, Testcase},
        inputs::value::I16Input,
        mutators::MutationResult,
        state::StdState,
    };

    #[test]
    fn all_mutate() {
        let mut corpus = InMemoryCorpus::new();
        corpus.add(Testcase::new(1_i16.into())).unwrap();
        let mut state = StdState::new(
            StdRand::new(),
            corpus,
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        let mut input: I16Input = 0_i16.into();

        let mutators = int_mutators().into_vec();

        for mut m in mutators {
            assert_eq!(
                MutationResult::Mutated,
                m.mutate(&mut state, &mut input).unwrap()
            );
        }
    }
}
