//! Tokens are what afl calls extras or dictionaries.
//! They may be inserted as part of mutations during fuzzing.

#[cfg(feature = "std")]
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::{
    inputs::{HasBytesVec, Input},
    mutators::*,
    state::{HasMaxSize, HasMetadata, HasRand},
    utils::Rand,
    Error,
};

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use mutations::buffer_copy;

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
    pub fn add_token(&mut self, token: &Vec<u8>) -> bool {
        if self.token_vec.contains(token) {
            return false;
        }
        self.token_vec.push(token.to_vec());
        return true;
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
            let start = line.chars().nth(0);
            if line.len() == 0 || start == Some('#') {
                continue;
            }
            let pos_quote = match line.find("\"") {
                Some(x) => x,
                _ => return Err(Error::IllegalArgument("Illegal line: ".to_owned() + line)),
            };
            if line.chars().nth(line.len() - 1) != Some('"') {
                return Err(Error::IllegalArgument("Illegal line: ".to_owned() + line));
            }

            // extract item
            let item = match line.get(pos_quote + 1..line.len() - 1) {
                Some(x) => x,
                _ => return Err(Error::IllegalArgument("Illegal line: ".to_owned() + line)),
            };
            if item.len() == 0 {
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
        return &self.token_vec;
    }
}

/// Insert a dictionary token
pub fn mutation_tokeninsert<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R> + HasMaxSize,
    R: Rand,
{
    let max_size = state.max_size();
    let tokens_len = {
        let meta = state.metadatas().get::<Tokens>();
        if meta.is_none() {
            return Ok(MutationResult::Skipped);
        }
        if meta.unwrap().tokens().len() == 0 {
            return Ok(MutationResult::Skipped);
        }
        meta.unwrap().tokens().len()
    };
    let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

    let size = input.bytes().len();
    let off = state.rand_mut().below((size + 1) as u64) as usize;

    let meta = state.metadatas().get::<Tokens>().unwrap();
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

/// Overwrite with a dictionary token
pub fn mutation_tokenreplace<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasMetadata + HasRand<R>,
    R: Rand,
{
    let size = input.bytes().len();
    if size == 0 {
        return Ok(MutationResult::Skipped);
    }

    let tokens_len = {
        let meta = state.metadatas().get::<Tokens>();
        if meta.is_none() {
            return Ok(MutationResult::Skipped);
        }
        if meta.unwrap().tokens().len() == 0 {
            return Ok(MutationResult::Skipped);
        }
        meta.unwrap().tokens().len()
    };
    let token_idx = state.rand_mut().below(tokens_len as u64) as usize;

    let off = state.rand_mut().below(size as u64) as usize;

    let meta = state.metadatas().get::<Tokens>().unwrap();
    let token = &meta.tokens()[token_idx];
    let mut len = token.len();
    if off + len > size {
        len = size - off;
    }

    buffer_copy(input.bytes_mut(), token, 0, off, len);

    Ok(MutationResult::Mutated)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::fs;

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
