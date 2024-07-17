use libafl_bolts::rands::Rand;
use serde::{Deserialize, Serialize};
use std::hash::{DefaultHasher, Hash, Hasher};

use libafl::{
    corpus::CorpusId, generators::Generator, inputs::Input, state::HasRand, Error, SerdeAny,
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
    Vec::with_capacity(rand.below(length))
        .iter()
        .map(|_: &u8| rand.next() as u8)
        .collect()
}

// impl Named for CustomInput {
//     fn name(&self) -> &Cow<'static, str> {
//         &Cow::Borrowed("CustomInput")
//     }
// }
