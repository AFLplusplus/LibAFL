//! Tokens are what afl calls extras or dictionaries.
//! They may be inserted as part of mutations during fuzzing.

use crate::{
    bolts::serdeany::SerdeAny,
    inputs::{HasBytesVec, Input},
    mutators::*,
    utils::Rand,
    Error,
};

use alloc::vec::Vec;
use core::any::Any;
use serde::{Deserialize, Serialize};

use mutations::buffer_copy;

/// A state metadata holding a list of tokens
#[derive(Serialize, Deserialize)]
pub struct TokensMetadata {
    tokens: Vec<Vec<u8>>,
}

impl SerdeAny for TokensMetadata {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl TokensMetadata {
    pub fn new(tokens: Vec<Vec<u8>>) -> Self {
        Self { tokens: tokens }
    }
}

/// Insert a dictionary token
pub fn mutation_tokeninsert<I, M, R, S>(
    mutator: &mut M,
    rand: &mut R,
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    M: HasMaxSize,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasMetadata,
{
    let meta;
    match state.metadata().get::<TokensMetadata>() {
        Some(t) => {
            meta = t;
        }
        None => {
            return Ok(MutationResult::Skipped);
        }
    };
    if meta.tokens.len() == 0 {
        return Ok(MutationResult::Skipped);
    }
    let token = &meta.tokens[rand.below(meta.tokens.len() as u64) as usize];

    let size = input.bytes().len();
    let off = rand.below((size + 1) as u64) as usize;
    let mut len = token.len();

    if size + len > mutator.max_size() {
        if mutator.max_size() > size {
            len = mutator.max_size() - size;
        } else {
            return Ok(MutationResult::Skipped);
        }
    }

    input.bytes_mut().resize(size + len, 0);
    buffer_self_copy(input.bytes_mut(), off, off + len, size - off);
    buffer_copy(input.bytes_mut(), token, 0, off, len);

    Ok(MutationResult::Mutated)
}

/// Overwrite with a dictionary token
pub fn mutation_tokenreplace<I, M, R, S>(
    _: &mut M,
    rand: &mut R,
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    R: Rand,
    S: HasMetadata,
{
    let size = input.bytes().len();
    if size == 0 {
        return Ok(MutationResult::Skipped);
    }

    let meta;
    match state.metadata().get::<TokensMetadata>() {
        Some(t) => {
            meta = t;
        }
        None => {
            return Ok(MutationResult::Skipped);
        }
    };
    if meta.tokens.len() == 0 {
        return Ok(MutationResult::Skipped);
    }
    let token = &meta.tokens[rand.below(meta.tokens.len() as u64) as usize];

    let off = rand.below(size as u64) as usize;

    let mut len = token.len();
    if off + len > size {
        len = size - off;
    }

    buffer_copy(input.bytes_mut(), token, 0, off, len);

    Ok(MutationResult::Mutated)
}
