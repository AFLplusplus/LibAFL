//! Tokens are what afl calls extras or dictionaries.
//! They may be inserted as part of mutations during fuzzing.

use crate::{
    bolts::serdeany::SerdeAny,
    inputs::{HasBytesVec, Input},
    mutators::*,
    utils::Rand,
    AflError,
};

use alloc::vec::Vec;
use core::any::Any;
use serde::{Deserialize, Serialize};

use mutations::buffer_copy;

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

/// Insert a dictionary token
pub fn mutation_tokeninsert<I, M, R, S>(
    mutator: &mut M,
    rand: &mut R,
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, AflError>
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
    let token_len = token.len();
    let size = input.bytes().len();
    let off = if size == 0 {
        0
    } else {
        rand.below(core::cmp::min(
            size as u64,
            (mutator.max_size() - token_len) as u64,
        )) as usize
    } as usize;

    input.bytes_mut().resize(size + token_len, 0);
    buffer_copy(input.bytes_mut(), token, 0, off, size);
    
    Ok(MutationResult::Mutated)
}

/// Overwrite with a dictionary token
pub fn mutation_tokenreplace<I, M, R, S>(
    mutator: &mut M,
    rand: &mut R,
    state: &S,
    input: &mut I,
) -> Result<MutationResult, AflError>
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
    let token_len = token.len();
    let size = input.bytes().len();
    let off = rand.below((mutator.max_size() - token_len) as u64) as usize;

    buffer_copy(input.bytes_mut(), token, 0, off, size);

    Ok(MutationResult::Mutated)
}
