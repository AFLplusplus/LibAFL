//! Tokens are what afl calls extras or dictionaries.
//! They may be inserted as part of mutations during fuzzing.
use alloc::vec::Vec;
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::{
    inputs::{HasBytesVec, Input},
    mutators::{buffer_self_copy, mutations, MutationResult, Mutator, Named},
    state::{HasMaxSize, HasMetadata, HasRand},
    utils::Rand,
    Error,
};
use mutations::buffer_copy;

#[cfg(feature = "std")]
use crate::mutators::str_decode;

/// A state metadata holding a list of tokens
#[derive(Serialize, Deserialize)]
pub struct Tokens {
    token_vec: Vec<Vec<u8>>,
}

crate::impl_serdeany!(Tokens);

/// The metadata used for token mutators
impl Tokens {
    /// Creates a new tokens metadata (old-skool afl name: `dictornary`)
    pub fn new(token_vec: Vec<Vec<u8>>) -> Self {
        Self { token_vec }
    }

    /// Creates a new instance from a file
    #[cfg(feature = "std")]
    pub fn from_tokens_file<P>(file: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut ret = Self::new(vec![]);
        ret.add_tokens_from_file(file)?;
        Ok(ret)
    }

    /// Adds a token to a dictionary, checking it is not a duplicate
    /// Returns `false` if the token was already present and did not get added.
    #[allow(clippy::ptr_arg)]
    pub fn add_token(&mut self, token: &Vec<u8>) -> bool {
        if self.token_vec.contains(token) {
            return false;
        }
        self.token_vec.push(token.to_vec());
        true
    }

    /// Reads a tokens file, returning the count of new entries read
    #[cfg(feature = "std")]
    pub fn add_tokens_from_file<P>(&mut self, file: P) -> Result<u32, Error>
    where
        P: AsRef<Path>,
    {
        let mut entries = 0;

        // println!("Loading tokens file {:?} ...", file);

        let file = File::open(file)?; // panic if not found
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.unwrap();
            let line = line.trim_start().trim_end();

            // we are only interested in '"..."', not prefixed 'foo = '
            let start = line.chars().next();
            if line.is_empty() || start == Some('#') {
                continue;
            }
            let pos_quote = match line.find('\"') {
                Some(x) => x,
                None => return Err(Error::IllegalArgument("Illegal line: ".to_owned() + line)),
            };
            if line.chars().nth(line.len() - 1) != Some('"') {
                return Err(Error::IllegalArgument("Illegal line: ".to_owned() + line));
            }

            // extract item
            let item = match line.get(pos_quote + 1..line.len() - 1) {
                Some(x) => x,
                None => return Err(Error::IllegalArgument("Illegal line: ".to_owned() + line)),
            };
            if item.is_empty() {
                continue;
            }

            // decode
            let token: Vec<u8> = match str_decode(item) {
                Ok(val) => val,
                Err(_) => {
                    return Err(Error::IllegalArgument(
                        "Illegal line (hex decoding): ".to_owned() + line,
                    ))
                }
            };

            // add
            if self.add_token(&token) {
                entries += 1;
            }
        }

        Ok(entries)
    }

    /// Gets the tokens stored in this db
    pub fn tokens(&self) -> &[Vec<u8>] {
        &self.token_vec
    }
}

/// Inserts a random token at a random position in the `Input`.
#[derive(Default)]
pub struct TokenInsert<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for TokenInsert<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let tokens_len = {
            let meta = state.metadata().get::<Tokens>();
            if meta.is_none() {
                return Ok(MutationResult::Skipped);
            }
            if meta.unwrap().tokens().is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.unwrap().tokens().len()
        };
        let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

        let size = input.bytes().len();
        let off = state.rand_mut().below((size + 1) as u64) as usize;

        let meta = state.metadata().get::<Tokens>().unwrap();
        let token = &meta.tokens()[token_idx];
        let mut len = token.len();

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        input.bytes_mut().resize(size + len, 0);
        buffer_self_copy(input.bytes_mut(), off, off + len, size - off);
        buffer_copy(input.bytes_mut(), token, 0, off, len);

        Ok(MutationResult::Mutated)
    }
}

impl<I, R, S> Named for TokenInsert<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn name(&self) -> &str {
        "TokenInsert"
    }
}

impl<I, R, S> TokenInsert<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    /// Create a `TokenInsert` `Mutation`.
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// A `TokenReplace` [`Mutator`] replaces a random part of the input with one of a range of tokens.
/// From AFL terms, this is called as `Dictionary` mutation (which doesn't really make sense ;) ).
#[derive(Default)]
pub struct TokenReplace<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for TokenReplace<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }

        let tokens_len = {
            let meta = state.metadata().get::<Tokens>();
            if meta.is_none() {
                return Ok(MutationResult::Skipped);
            }
            if meta.unwrap().tokens().is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.unwrap().tokens().len()
        };
        let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

        let off = state.rand_mut().below(size as u64) as usize;

        let meta = state.metadata().get::<Tokens>().unwrap();
        let token = &meta.tokens()[token_idx];
        let mut len = token.len();
        if off + len > size {
            len = size - off;
        }

        buffer_copy(input.bytes_mut(), token, 0, off, len);

        Ok(MutationResult::Mutated)
    }
}

impl<I, R, S> Named for TokenReplace<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn name(&self) -> &str {
        "TokenReplace"
    }
}

impl<I, R, S> TokenReplace<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    /// Creates a new `TokenReplace` struct.
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::fs;

    #[cfg(feature = "std")]
    use super::Tokens;

    #[cfg(feature = "std")]
    #[test]
    fn test_read_tokens() {
        let _ = fs::remove_file("test.tkns");
        let data = r###"
# comment
token1@123="AAA"
token1="A\x41A"
"A\AA"
token2="B"
        "###;
        fs::write("test.tkns", data).expect("Unable to write test.tkns");
        let tokens = Tokens::from_tokens_file(&"test.tkns").unwrap();
        #[cfg(feature = "std")]
        println!("Token file entries: {:?}", tokens.tokens());
        assert_eq!(tokens.tokens().len(), 2);
        let _ = fs::remove_file("test.tkns");
    }
}
