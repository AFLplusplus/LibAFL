use core::num::NonZeroUsize;
use std::{borrow::Cow, hash::Hash};

use libafl::{
    generators::{Generator, RandBytesGenerator},
    inputs::{BytesInput, HasTargetBytes, Input},
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error, SerdeAny,
};
use libafl_bolts::{rands::Rand, Named};
use serde::{Deserialize, Serialize};

/// The custom [`Input`] type used in this example, consisting of a byte array part, a byte array that is not always present, and a boolean
///
/// Imagine these could be used to model command line arguments for a bash command, where
/// - `byte_array` is binary data that is always needed like what is passed to stdin,
/// - `optional_byte_array` is binary data passed as a command line arg, and it is only passed if it is not `None` in the input,
/// - `num` is an arbitrary number (`i16` in this case)
/// - `boolean` models the presence or absence of a command line flag that does not require additional data
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct CustomInput {
    pub byte_array: Vec<u8>,
    pub optional_byte_array: Option<Vec<u8>>,
    pub num: i16,
    pub boolean: bool,
}

/// Hash-based implementation
impl Input for CustomInput {}

impl CustomInput {
    /// Returns a mutable reference to the byte array
    pub fn byte_array_mut(&mut self) -> &mut Vec<u8> {
        &mut self.byte_array
    }

    /// Returns an immutable reference to the byte array
    pub fn byte_array(&self) -> &Vec<u8> {
        &self.byte_array
    }

    /// Returns a mutable reference to the optional byte array
    pub fn optional_byte_array_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.optional_byte_array
    }

    /// Returns an immutable reference to the optional byte array
    pub fn optional_byte_array(&self) -> &Option<Vec<u8>> {
        &self.optional_byte_array
    }

    /// Returns a mutable reference to the number
    pub fn num_mut(&mut self) -> &mut i16 {
        &mut self.num
    }

    /// Returns an immutable reference to the number
    pub fn num(&self) -> &i16 {
        &self.num
    }
}

/// A generator for [`CustomInput`] used in this example
pub struct CustomInputGenerator {
    pub bytes_generator: RandBytesGenerator,
}

impl CustomInputGenerator {
    /// Creates a new [`CustomInputGenerator`]
    pub fn new(max_len: NonZeroUsize) -> Self {
        Self {
            bytes_generator: RandBytesGenerator::new(max_len),
        }
    }
}

impl<S> Generator<CustomInput, S> for CustomInputGenerator
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<CustomInput, Error> {
        let generator = &mut self.bytes_generator;

        let byte_array = generator.generate(state).unwrap().target_bytes().into();
        let optional_byte_array = state
            .rand_mut()
            .coinflip(0.5)
            .then(|| generator.generate(state).unwrap().target_bytes().into());
        let boolean = state.rand_mut().coinflip(0.5);
        let num = state.rand_mut().next() as i16;

        Ok(CustomInput {
            byte_array,
            optional_byte_array,
            num,
            boolean,
        })
    }
}

/// [`Mutator`] that toggles the optional byte array of a [`CustomInput`], i.e. sets it to [`None`] if it is not, and to a random byte array if it is [`None`]
pub struct ToggleOptionalByteArrayMutator<G> {
    generator: G,
}

impl ToggleOptionalByteArrayMutator<RandBytesGenerator> {
    /// Creates a new [`ToggleOptionalByteArrayMutator`]
    pub fn new(length: NonZeroUsize) -> Self {
        Self {
            generator: RandBytesGenerator::new(length),
        }
    }
}

impl<G, S> Mutator<CustomInput, S> for ToggleOptionalByteArrayMutator<G>
where
    S: HasRand,
    G: Generator<BytesInput, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut CustomInput) -> Result<MutationResult, Error> {
        input.optional_byte_array = match input.optional_byte_array {
            None => Some(self.generator.generate(state)?.target_bytes().into()),
            Some(_) => None,
        };
        Ok(MutationResult::Mutated)
    }
}

impl<G> Named for ToggleOptionalByteArrayMutator<G> {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ToggleOptionalByteArrayMutator")
    }
}

/// [`Mutator`] that toggles the boolean field in a [`CustomInput`]
pub struct ToggleBooleanMutator;

impl<S> Mutator<CustomInput, S> for ToggleBooleanMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut CustomInput) -> Result<MutationResult, Error> {
        input.boolean = !input.boolean;
        Ok(MutationResult::Mutated)
    }
}

impl Named for ToggleBooleanMutator {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("ToggleBooleanMutator")
    }
}
