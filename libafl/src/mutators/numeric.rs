//! Mutators for integer-style inputs

use alloc::borrow::Cow;

use libafl_bolts::{
    rands::Rand,
    tuples::{Map as _, Merge},
    Error, Named,
};
use tuple_list::{tuple_list, tuple_list_type};

use super::{MappingMutator, MutationResult, Mutator, ToMappingMutator};
use crate::{
    corpus::Corpus,
    random_corpus_id_with_disabled,
    state::{HasCorpus, HasRand},
};

/// All mutators for integer-like inputs
pub type IntMutatorsType = tuple_list_type!(
    BitFlipMutator,
    NegateMutator,
    IncMutator,
    DecMutator,
    TwosComplementMutator,
    RandMutator,
    CrossoverMutator
);
type IntMutatorsCrossoverType = tuple_list_type!(CrossoverMutator);
type MappedIntMutatorsCrossoverType<F> = tuple_list_type!(MappedCrossoverMutator<F>);
type IntMutatorsNoCrossoverType = tuple_list_type!(
    BitFlipMutator,
    NegateMutator,
    IncMutator,
    DecMutator,
    TwosComplementMutator,
    RandMutator,
);

/// Mutators for integer-like inputs without crossover mutations
#[must_use]
pub fn int_mutators_no_crossover() -> IntMutatorsNoCrossoverType {
    tuple_list!(
        BitFlipMutator,
        NegateMutator,
        IncMutator,
        DecMutator,
        TwosComplementMutator,
        RandMutator,
    )
}

/// Mutators for integer-like inputs that implement some form of crossover
#[must_use]
pub fn int_mutators_crossover() -> IntMutatorsCrossoverType {
    tuple_list!(CrossoverMutator)
}

/// Mutators for integer-like inputs that implement some form of crossover with a mapper to extract the crossed over information.
#[must_use]
pub fn mapped_int_mutators_crossover<F>(input_mapper: F) -> MappedIntMutatorsCrossoverType<F> {
    tuple_list!(MappedCrossoverMutator::new(input_mapper))
}

/// Mutators for integer-like inputs
///
/// Modelled after the applicable mutators from [`super::havoc_mutations::havoc_mutations`]
#[must_use]
pub fn int_mutators() -> IntMutatorsType {
    int_mutators_no_crossover().merge(int_mutators_crossover())
}

/// Mapped mutators for integer-like inputs
pub type MappedIntMutatorsType<F1, F2> = tuple_list_type!(
    MappingMutator<BitFlipMutator,F1>,
    MappingMutator<NegateMutator,F1>,
    MappingMutator<IncMutator,F1>,
    MappingMutator<DecMutator,F1>,
    MappingMutator<TwosComplementMutator,F1>,
    MappingMutator<RandMutator,F1>,
    MappingMutator<MappedCrossoverMutator<F2>,F1>
);

/// Mapped mutators for integer-like inputs
///
/// Modelled after the applicable mutators from [`super::havoc_mutations::havoc_mutations`]
pub fn mapped_int_mutators<F1, F2, IO, II>(
    current_input_mapper: F1,
    input_from_corpus_mapper: F2,
) -> MappedIntMutatorsType<F1, F2>
where
    F1: Clone + FnMut(&mut IO) -> &mut II,
{
    int_mutators_no_crossover()
        .merge(mapped_int_mutators_crossover(input_from_corpus_mapper))
        .map(ToMappingMutator::new(current_input_mapper))
}
/// Functionality required for Numeric Mutators (see [`int_mutators`])
pub trait Numeric {
    /// Flip all bits of the number.
    fn flip_all_bits(&mut self);

    /// Flip the bit at the specified offset.
    ///
    /// # Safety
    ///
    /// Panics if the `offset` is out of bounds for the type
    fn flip_bit_at(&mut self, offset: usize);

    /// Increment the number by one, wrapping around on overflow.
    fn wrapping_inc(&mut self);

    /// Decrement the number by one, wrapping around on underflow.
    fn wrapping_dec(&mut self);

    /// Compute the two's complement of the number.
    fn twos_complement(&mut self);

    /// Randomizes the value using the provided random number generator.
    fn randomize<R: Rand>(&mut self, rand: &mut R);
}

// Macro to implement the Numeric trait for multiple integer types a u64 can be cast to
macro_rules! impl_numeric_cast_randomize {
    ($($t:ty)*) => ($(
        impl Numeric for $t {
            #[inline]
            fn flip_all_bits(&mut self) {
                *self = !*self;
            }

            #[inline]
            fn flip_bit_at(&mut self, offset: usize) {
                *self ^= 1 << offset;
            }

            #[inline]
            fn wrapping_inc(&mut self) {
                *self = self.wrapping_add(1);
            }

            #[inline]
            fn wrapping_dec(&mut self) {
                *self = self.wrapping_sub(1);
            }

            #[inline]
            fn twos_complement(&mut self) {
                *self = self.wrapping_neg();
            }

            #[inline]
            #[allow(trivial_numeric_casts, clippy::cast_possible_wrap)] // only for some macro calls
            fn randomize<R: Rand>(&mut self, rand: &mut R) {
                *self = rand.next() as $t;
            }

        }
    )*)
}

impl_numeric_cast_randomize!( u8 u16 u32 u64 usize i8 i16 i32 i64 isize );

// Macro to implement the Numeric trait for multiple integer types a u64 cannot be cast to
macro_rules! impl_numeric_128_bits_randomize {
    ($($t:ty)*) => ($(
        impl Numeric for $t {
            #[inline]
            fn flip_all_bits(&mut self) {
                *self = !*self;
            }

            #[inline]
            fn flip_bit_at(&mut self, offset: usize) {
                *self ^= 1 << offset;
            }

            #[inline]
            fn wrapping_inc(&mut self) {
                *self = self.wrapping_add(1);
            }

            #[inline]
            fn wrapping_dec(&mut self) {
                *self = self.wrapping_sub(1);
            }

            #[inline]
            fn twos_complement(&mut self) {
                *self = self.wrapping_neg();
            }

            #[inline]
            #[allow(trivial_numeric_casts, clippy::cast_possible_wrap)] // only for some macro calls
            fn randomize<R: Rand>(&mut self, rand: &mut R) {
                *self = (u128::from(rand.next()) << 64 | u128::from(rand.next())) as $t;
            }

        }
    )*)
}

// Apply the macro to all desired integer types
impl_numeric_128_bits_randomize! { u128 i128 }

impl<I: Numeric> Numeric for &mut I {
    fn flip_all_bits(&mut self) {
        (*self).flip_all_bits();
    }

    fn flip_bit_at(&mut self, offset: usize) {
        (*self).flip_bit_at(offset);
    }

    fn wrapping_inc(&mut self) {
        (*self).wrapping_inc();
    }

    fn wrapping_dec(&mut self) {
        (*self).wrapping_dec();
    }

    fn twos_complement(&mut self) {
        (*self).twos_complement();
    }

    fn randomize<R: Rand>(&mut self, rand: &mut R) {
        (*self).randomize(rand);
    }
}

/// Bitflip mutation for integer-like inputs
#[derive(Debug)]
pub struct BitFlipMutator;

impl<I, S> Mutator<I, S> for BitFlipMutator
where
    S: HasRand,
    I: Numeric,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let offset = state.rand_mut().choose(0..size_of::<I>()).unwrap();
        input.flip_bit_at(offset);
        Ok(MutationResult::Mutated)
    }
}

impl Named for BitFlipMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("BitFlipMutator")
    }
}

/// Negate mutation for integer-like inputs, i.e. flip all bits
#[derive(Debug)]
pub struct NegateMutator;

impl<I, S> Mutator<I, S> for NegateMutator
where
    I: Numeric,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        input.flip_all_bits();
        Ok(MutationResult::Mutated)
    }
}

impl Named for NegateMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ByteFlipMutator")
    }
}

/// Increment mutation for integer-like inputs. Wraps on overflows.
#[derive(Debug)]
pub struct IncMutator;

impl<I, S> Mutator<I, S> for IncMutator
where
    I: Numeric,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        input.wrapping_inc();
        Ok(MutationResult::Mutated)
    }
}

impl Named for IncMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("IncMutator")
    }
}

/// Decrement mutation for integer-like inputs. Wraps on underflow.
#[derive(Debug)]
pub struct DecMutator;

impl<I, S> Mutator<I, S> for DecMutator
where
    I: Numeric,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        input.wrapping_dec();
        Ok(MutationResult::Mutated)
    }
}

impl Named for DecMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("DecMutator")
    }
}

/// Two's complement mutation for integer-like inputs
#[derive(Debug)]
pub struct TwosComplementMutator;

impl<I, S> Mutator<I, S> for TwosComplementMutator
where
    I: Numeric,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        input.twos_complement();
        Ok(MutationResult::Mutated)
    }
}

impl Named for TwosComplementMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("NegMutator")
    }
}

/// Randomize mutation for integer-like inputs
#[derive(Debug)]
pub struct RandMutator;

impl<I, S> Mutator<I, S> for RandMutator
where
    S: HasRand,
    I: Numeric,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        // set to random data byte-wise since the RNGs don't work for all numeric types
        input.randomize(state.rand_mut());
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
/// Crossover mutation for integer-like inputs with custom state extraction function
#[derive(Debug)]
pub struct MappedCrossoverMutator<F> {
    input_mapper: F,
}

impl<F> MappedCrossoverMutator<F> {
    /// Create a new [`MappedCrossoverMutator`]
    pub fn new(input_mapper: F) -> Self {
        Self { input_mapper }
    }
}

impl<I, S, F> Mutator<I, S> for MappedCrossoverMutator<F>
where
    S: HasRand + HasCorpus,
    for<'b> F: Fn(&'b <S::Corpus as Corpus>::Input) -> &'b I,
    I: Clone,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let id = random_corpus_id_with_disabled!(state.corpus(), state.rand_mut());

        if state.corpus().current().is_some_and(|cur| cur == id) {
            return Ok(MutationResult::Skipped);
        }

        let other_testcase = state.corpus().get_from_all(id)?.borrow_mut();
        let other_input = other_testcase.input().as_ref().unwrap();
        let mapped_input = (self.input_mapper)(other_input).clone();
        *input = mapped_input;
        Ok(MutationResult::Mutated)
    }
}

impl<F> Named for MappedCrossoverMutator<F> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("MappedCrossoverMutator")
    }
}

#[cfg(test)]
mod tests {

    use libafl_bolts::{
        rands::{Rand, XkcdRand},
        tuples::IntoVec as _,
    };
    use serde::{Deserialize, Serialize};

    use super::{int_mutators, Numeric};
    use crate::{
        corpus::{Corpus as _, InMemoryCorpus, Testcase},
        inputs::value::I16Input,
        mutators::MutationResult,
        state::StdState,
    };

    #[test]
    fn randomized() {
        const RAND_NUM: u64 = 0xAAAAAAAAAAAAAAAA; // 0b10101010..
        #[derive(Serialize, Deserialize, Debug)]
        struct FixedRand;
        impl Rand for FixedRand {
            fn set_seed(&mut self, _seed: u64) {}
            fn next(&mut self) -> u64 {
                RAND_NUM
            }
        }

        let rand = &mut FixedRand;

        let mut i = 0_u8;
        Numeric::randomize(&mut i, rand);
        assert_eq!(0xAA, i);

        let mut i = 0_u128;
        Numeric::randomize(&mut i, rand);
        assert_eq!(((u128::from(RAND_NUM) << 64) | u128::from(RAND_NUM)), i);

        let mut i = 0_i16;
        Numeric::randomize(&mut i, rand);
        assert_eq!(-0b101010101010110, i); // two's complement
    }

    #[test]
    fn all_mutate_owned() {
        let mut corpus = InMemoryCorpus::new();
        corpus.add(Testcase::new(42_i16.into())).unwrap();
        let mut state = StdState::new(
            XkcdRand::new(),
            corpus,
            InMemoryCorpus::new(),
            &mut (),
            &mut (),
        )
        .unwrap();

        let mutators = int_mutators().into_vec();

        for mut m in mutators {
            let mut input: I16Input = 1_i16.into();
            assert_eq!(
                MutationResult::Mutated,
                m.mutate(&mut state, &mut input).unwrap(),
                "Errored with {}",
                m.name()
            );
            assert_ne!(1, input.into_inner(), "Errored with {}", m.name());
        }
    }
}
