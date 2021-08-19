//! The `EncodedInput` is the "normal" input, a map of codes, that can be sent directly to the client
//! (As opposed to other, more abstract, imputs, like an Grammar-Based AST Input)

use ahash::AHasher;
use core::hash::Hasher;

use alloc::{borrow::ToOwned, rc::Rc, string::String, vec::Vec};
use core::{cell::RefCell, convert::From, str::from_utf8};
use hashbrown::HashMap;
#[cfg(feature = "std")]
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::inputs::{HasLen, Input};
#[cfg(feature = "std")]
use crate::Error;

pub trait InputEncoder<T>
where
    T: Tokenizer,
{
    fn encode(&mut self, bytes: &[u8], tokenizer: &mut T) -> Result<EncodedInput, Error>;
}

pub trait InputDecoder {
    fn decode(&self, input: &EncodedInput, bytes: &mut Vec<u8>) -> Result<(), Error>;
}

pub trait Tokenizer {
    fn tokenize(&self, bytes: &[u8]) -> Result<Vec<String>, Error>;
}

pub struct TokenInputEncoderDecoder {
    token_table: HashMap<String, u32>,
    id_table: HashMap<u32, String>,
    next_id: u32,
}

impl<T> InputEncoder<T> for TokenInputEncoderDecoder
where
    T: Tokenizer,
{
    fn encode(&mut self, bytes: &[u8], tokenizer: &mut T) -> Result<EncodedInput, Error> {
        let mut codes = vec![];
        let tokens = tokenizer.tokenize(bytes)?;
        for tok in tokens {
            if let Some(id) = self.token_table.get(&tok) {
                codes.push(*id);
            } else {
                self.token_table.insert(tok.to_owned(), self.next_id);
                self.id_table.insert(self.next_id, tok.to_owned());
                codes.push(self.next_id);
                self.next_id += 1;
            }
        }
        Ok(EncodedInput::new(codes))
    }
}

impl InputDecoder for TokenInputEncoderDecoder {
    fn decode(&self, input: &EncodedInput, bytes: &mut Vec<u8>) -> Result<(), Error> {
        for id in input.codes() {
            let tok = self.id_table.get(&(id % self.next_id)).ok_or_else(|| {
                Error::IllegalState(format!("Id {} not in the decoder table", id))
            })?;
            bytes.extend_from_slice(tok.as_bytes());
            bytes.push(b' ');
        }
        Ok(())
    }
}

impl TokenInputEncoderDecoder {
    pub fn new() -> Self {
        Self {
            token_table: HashMap::default(),
            id_table: HashMap::default(),
            next_id: 0,
        }
    }
}

#[cfg(feature = "std")]
pub struct NaiveTokenizer {
    ident_re: Regex,
}

#[cfg(feature = "std")]
impl NaiveTokenizer {
    pub fn new() -> Self {
        Self {
            ident_re: Regex::new("[A-Za-z0-9_$]+").unwrap(),
        }
    }
}

#[cfg(feature = "std")]
impl Tokenizer for NaiveTokenizer {
    fn tokenize(&self, bytes: &[u8]) -> Result<Vec<String>, Error> {
        let mut tokens = vec![];
        let string =
            from_utf8(bytes).map_err(|_| Error::IllegalArgument("Invalid UTF-8".to_owned()))?;
        for ws_tok in string.split_whitespace() {
            let mut prev = 0;
            for pair in self.ident_re.find_iter(ws_tok) {
                if pair.start() > prev {
                    tokens.push(ws_tok[prev..pair.start()].to_owned());
                }
                tokens.push(ws_tok[pair.start()..pair.end()].to_owned());
                prev = pair.end();
            }
            if prev < ws_tok.len() {
                tokens.push(ws_tok[prev..].to_owned());
            }
        }
        Ok(tokens)
    }
}

/// A codes input is the basic input
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct EncodedInput {
    /// The input representation as list of codes
    codes: Vec<u32>,
}

impl Input for EncodedInput {
    /// Generate a name for this input
    fn generate_name(&self, _idx: usize) -> String {
        let mut hasher = AHasher::new_with_keys(0, 0);
        for code in &self.codes {
            hasher.write(&code.to_le_bytes());
        }
        format!("{:016x}", hasher.finish())
    }
}

/// Rc Ref-cell from Input
impl From<EncodedInput> for Rc<RefCell<EncodedInput>> {
    fn from(input: EncodedInput) -> Self {
        Rc::new(RefCell::new(input))
    }
}

impl HasLen for EncodedInput {
    #[inline]
    fn len(&self) -> usize {
        self.codes.len()
    }
}

impl From<Vec<u32>> for EncodedInput {
    fn from(codes: Vec<u32>) -> Self {
        Self::new(codes)
    }
}

impl From<&[u32]> for EncodedInput {
    fn from(codes: &[u32]) -> Self {
        Self::new(codes.to_owned())
    }
}

impl EncodedInput {
    /// Creates a new codes input using the given codes
    #[must_use]
    pub fn new(codes: Vec<u32>) -> Self {
        Self { codes }
    }

    pub fn codes(&self) -> &[u32] {
        &self.codes
    }

    pub fn codes_mut(&mut self) -> &mut [u32] {
        &mut self.codes
    }
}

#[cfg(test)]
mod tests {
    use crate::inputs::encoded::{
        InputDecoder, InputEncoder, NaiveTokenizer, TokenInputEncoderDecoder,
    };
    use core::str::from_utf8;

    #[test]
    fn test_input() {
        let mut t = NaiveTokenizer::new();
        let mut ed = TokenInputEncoderDecoder::new();
        let input = ed.encode("a = 1; b=c+a\n".as_bytes(), &mut t).unwrap();
        let mut bytes = vec![];
        ed.decode(&input, &mut bytes).unwrap();
        assert_eq!(from_utf8(&bytes).unwrap(), "a = 1 ; b = c + a ".to_owned());
    }
}
