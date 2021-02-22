//! Tokens are what afl calls extras or dictionaries.
//! They may be inserted as part of mutations during fuzzing.

use crate::{
    inputs::{HasBytesVec, Input},
    mutators::*,
    state::{HasMetadata, HasRand},
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

crate::impl_serdeany!(TokensMetadata);

impl TokensMetadata {
    pub fn new(tokens: Vec<Vec<u8>>) -> Self {
        Self { tokens: tokens }
    }
}

/// Insert a dictionary token
pub fn mutation_tokeninsert<F, I, M, R, S>(
    mutator: &M,
    _: &F,
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    M: HasMaxSize,
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R>,
    R: Rand,
{
    let tokens_len = {
        let meta = state.metadata().get::<TokensMetadata>();
        if meta.is_none() {
            return Ok(MutationResult::Skipped);
        }
        if meta.unwrap().tokens.len() == 0 {
            return Ok(MutationResult::Skipped);
        }
        meta.unwrap().tokens.len()
    };
    let token_idx = state.rand_mut().below(tokens_len as u64) as usize;
    
    let size = input.bytes().len();
    let off = state.rand_mut().below((size + 1) as u64) as usize;

    let meta = state.metadata().get::<TokensMetadata>().unwrap();
    let token = &meta.tokens[token_idx];
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
pub fn mutation_tokenreplace<F, I, M, R, S>(
    _: &M,
    _: &F,
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    M: HasMaxSize,
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R>,
    R: Rand,
{
    let size = input.bytes().len();
    if size == 0 {
        return Ok(MutationResult::Skipped);
    }

    let tokens_len = {
        let meta = state.metadata().get::<TokensMetadata>();
        if meta.is_none() {
            return Ok(MutationResult::Skipped);
        }
        if meta.unwrap().tokens.len() == 0 {
            return Ok(MutationResult::Skipped);
        }
        meta.unwrap().tokens.len()
    };
    let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

    let off = state.rand_mut().below(size as u64) as usize;

    let meta = state.metadata().get::<TokensMetadata>().unwrap();
    let token = &meta.tokens[token_idx];
    let mut len = token.len();
    if off + len > size {
        len = size - off;
    }

    buffer_copy(input.bytes_mut(), token, 0, off, len);

    Ok(MutationResult::Mutated)
}
