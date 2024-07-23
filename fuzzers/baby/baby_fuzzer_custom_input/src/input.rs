use libafl_bolts::{rands::Rand, Named};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    hash::{DefaultHasher, Hash, Hasher},
};

use libafl::{
    corpus::CorpusId,
    generators::Generator,
    inputs::Input,
    prelude::{MutationResult, Mutator},
    state::HasRand,
    Error, SerdeAny,
};

#[derive(Serialize, Deserialize, Clone, Debug, Hash, SerdeAny)]
pub struct CustomInput {
    pub byte_array: Vec<u8>,
    pub optional_byte_array: Option<Vec<u8>>,
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
    pub fn byte_array_mut(&mut self) -> &mut Vec<u8> {
        &mut self.byte_array
    }

    pub fn byte_array_optional(&self) -> Option<&Vec<u8>> {
        Some(&self.byte_array)
    }

    pub fn optional_byte_array_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.optional_byte_array
    }
    pub fn optional_byte_array_optional(&self) -> Option<&Vec<u8>> {
        self.optional_byte_array.as_ref()
    }
}

pub struct CustomInputGenerator {
    pub max_len: usize,
}

impl CustomInputGenerator {
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
        let boolean = state.rand_mut().coinflip(0.5);

        Ok(CustomInput {
            byte_array,
            optional_byte_array,
            boolean,
        })
    }
}

fn generate_bytes<S: HasRand>(length: usize, state: &mut S) -> Vec<u8> {
    let rand = state.rand_mut();
    let len = rand.between(1, length);
    let mut vec = Vec::new();
    vec.resize_with(len, || rand.next() as u8);
    vec
}

pub struct ToggleOptionalByteArrayMutator {
    length: usize,
}

impl ToggleOptionalByteArrayMutator {
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
