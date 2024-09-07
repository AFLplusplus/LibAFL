use std::{
    borrow::Cow,
    hash::{DefaultHasher, Hash, Hasher},
};

use libafl::{
    corpus::CorpusId,
    generators::Generator,
    inputs::{Input, MutVecInput},
    prelude::{MutationResult, Mutator},
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
/// - `boolean` models the presence or absence of a command line flag that does not require additional data
#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct CustomInput {
    pub byte_array: Vec<u8>,
    pub optional_byte_array: Option<Vec<u8>>,
    pub byte_array_custom_mapper: Vec<u8>,
    pub boolean: bool,
}

/// Hash-based implementation
impl Input for CustomInput {
    fn generate_name(&self, _id: Option<CorpusId>) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

impl CustomInput {
    /// Returns a mutable reference to the byte array
    pub fn byte_array_mut(&mut self) -> &mut Vec<u8> {
        &mut self.byte_array
    }

    /// Returns an immutable reference to the byte array wrapped in [`Some`]
    pub fn byte_array_optional(&self) -> Option<&[u8]> {
        Some(&self.byte_array)
    }

    /// Returns a mutable reference to the optional byte array
    pub fn optional_byte_array_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.optional_byte_array
    }

    /// Returns an immutable reference to the optional byte array
    pub fn optional_byte_array_optional(&self) -> Option<&[u8]> {
        self.optional_byte_array.as_deref()
    }

    pub fn byte_array_custom_mapper(&mut self) -> MutVecInput<'_> {
        MutVecInput::from(&mut self.byte_array_custom_mapper)
    }

    pub fn byte_array_custom_mapper_corpus_extractor(&self) -> Option<&[u8]> {
        Some(&self.byte_array_custom_mapper)
    }
}

/// A generator for [`CustomInput`] used in this example
pub struct CustomInputGenerator {
    pub max_len: usize,
}

impl CustomInputGenerator {
    /// Creates a new [`CustomInputGenerator`]
    pub fn new(max_len: usize) -> Self {
        Self { max_len }
    }
}

impl<S> Generator<CustomInput, S> for CustomInputGenerator
where
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<CustomInput, Error> {
        let byte_array = generate_bytes(self.max_len, state);
        let optional_byte_array = state
            .rand_mut()
            .coinflip(0.5)
            .then(|| generate_bytes(self.max_len, state));
        let byte_array_custom_mapper = generate_bytes(self.max_len, state);
        let boolean = state.rand_mut().coinflip(0.5);

        Ok(CustomInput {
            byte_array,
            optional_byte_array,
            byte_array_custom_mapper,
            boolean,
        })
    }
}

/// Generate a [`Vec<u8>`] of a length between 1 (incl.) and `length` (incl.) filled with random bytes
fn generate_bytes<S: HasRand>(length: usize, state: &mut S) -> Vec<u8> {
    let rand = state.rand_mut();
    let len = rand.between(1, length);
    let mut vec = Vec::new();
    vec.resize_with(len, || rand.next() as u8);
    vec
}

/// [`Mutator`] that toggles the optional byte array of a [`CustomInput`], i.e. sets it to [`None`] if it is not, and to a random byte array if it is [`None`]
pub struct ToggleOptionalByteArrayMutator {
    length: usize,
}

impl ToggleOptionalByteArrayMutator {
    /// Creates a new [`ToggleOptionalByteArrayMutator`]
    pub fn new(length: usize) -> Self {
        Self { length }
    }
}

impl<S> Mutator<CustomInput, S> for ToggleOptionalByteArrayMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut CustomInput) -> Result<MutationResult, Error> {
        input.optional_byte_array = match input.optional_byte_array {
            None => Some(generate_bytes(self.length, state)),
            Some(_) => None,
        };
        Ok(MutationResult::Mutated)
    }
}

impl Named for ToggleOptionalByteArrayMutator {
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
