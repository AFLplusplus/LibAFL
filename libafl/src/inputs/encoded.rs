//! The `EncodedInput` is the "normal" input, a map of codes, that can be sent directly to the client
//! (As opposed to other, more abstract, inputs, like an Grammar-Based AST Input)
//! See also [the paper on token-level fuzzing](https://www.usenix.org/system/files/sec21-salls.pdf)

#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::{borrow::ToOwned, rc::Rc, string::String, vec::Vec};
#[cfg(feature = "std")]
use core::str::from_utf8;
use core::{cell::RefCell, convert::From, hash::Hasher};

use ahash::AHasher;
use hashbrown::HashMap;
#[cfg(feature = "std")]
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{bolts::HasLen, inputs::Input, Error};

/// Trait to encode bytes to an [`EncodedInput`] using the given [`Tokenizer`]
pub trait InputEncoder<T>
where
    T: Tokenizer,
{
    /// Encode bytes to an [`EncodedInput`] using the given [`Tokenizer`]
    fn encode(&mut self, bytes: &[u8], tokenizer: &mut T) -> Result<EncodedInput, Error>;
}

/// Trait to decode encoded input to bytes
pub trait InputDecoder {
    /// Decode encoded input to bytes
    #[allow(clippy::ptr_arg)] // we reuse the alloced `Vec`
    fn decode(&self, input: &EncodedInput, bytes: &mut Vec<u8>) -> Result<(), Error>;
}

/// Tokenizer is a trait that can tokenize bytes into a [`Vec`] of tokens
pub trait Tokenizer {
    /// Tokenize the given bytes
    fn tokenize(&self, bytes: &[u8]) -> Result<Vec<String>, Error>;
}

/// A token input encoder/decoder
#[derive(Clone, Debug)]
pub struct TokenInputEncoderDecoder {
    /// The table of tokens
    token_table: HashMap<String, u32>,
    /// The table of ids
    id_table: HashMap<u32, String>,
    /// The next id
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
                self.token_table.insert(tok.clone(), self.next_id);
                self.id_table.insert(self.next_id, tok.clone());
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
            let tok = self
                .id_table
                .get(&(id % self.next_id))
                .ok_or_else(|| Error::illegal_state(format!("Id {id} not in the decoder table")))?;
            bytes.extend_from_slice(tok.as_bytes());
            bytes.push(b' ');
        }
        Ok(())
    }
}

impl TokenInputEncoderDecoder {
    /// Creates a new [`TokenInputEncoderDecoder`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            token_table: HashMap::default(),
            id_table: HashMap::default(),
            next_id: 0,
        }
    }
}

impl Default for TokenInputEncoderDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// A naive tokenizer struct
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct NaiveTokenizer {
    /// Ident regex
    ident_re: Regex,
    /// Comment regex
    comment_re: Regex,
    /// String regex
    string_re: Regex,
}

#[cfg(feature = "std")]
impl NaiveTokenizer {
    /// Creates a new [`NaiveTokenizer`]
    #[must_use]
    pub fn new(ident_re: Regex, comment_re: Regex, string_re: Regex) -> Self {
        Self {
            ident_re,
            comment_re,
            string_re,
        }
    }
}

#[cfg(feature = "std")]
impl Default for NaiveTokenizer {
    fn default() -> Self {
        Self {
            // Generic identifier regex
            ident_re: Regex::new("[A-Za-z0-9_$]+").unwrap(),
            // C++ style comments
            comment_re: Regex::new(r"(/\*[^*]*\*/)|(//[^*]*)").unwrap(),
            // " and ' string regex
            string_re: Regex::new("\"(\\\\|\\\\\"|[^\"])*\"|'(\\\\|\\\\'|[^'])*'").unwrap(),
        }
    }
}

#[cfg(feature = "std")]
impl Tokenizer for NaiveTokenizer {
    fn tokenize(&self, bytes: &[u8]) -> Result<Vec<String>, Error> {
        let mut tokens = vec![];
        let string =
            from_utf8(bytes).map_err(|_| Error::illegal_argument("Invalid UTF-8".to_owned()))?;
        let string = self.comment_re.replace_all(string, "").to_string();
        let mut str_prev = 0;
        for str_match in self.string_re.find_iter(&string) {
            if str_match.start() > str_prev {
                for ws_tok in string[str_prev..str_match.start()].split_whitespace() {
                    let mut ident_prev = 0;
                    for ident_match in self.ident_re.find_iter(ws_tok) {
                        if ident_match.start() > ident_prev {
                            tokens.push(ws_tok[ident_prev..ident_match.start()].to_owned());
                        }
                        tokens.push(ws_tok[ident_match.start()..ident_match.end()].to_owned());
                        ident_prev = ident_match.end();
                    }
                    if ident_prev < ws_tok.len() {
                        tokens.push(ws_tok[ident_prev..].to_owned());
                    }
                }
            }
            tokens.push(string[str_match.start()..str_match.end()].to_owned());
            str_prev = str_match.end();
        }
        if str_prev < string.len() {
            for ws_tok in string[str_prev..].split_whitespace() {
                let mut ident_prev = 0;
                for ident_match in self.ident_re.find_iter(ws_tok) {
                    if ident_match.start() > ident_prev {
                        tokens.push(ws_tok[ident_prev..ident_match.start()].to_owned());
                    }
                    tokens.push(ws_tok[ident_match.start()..ident_match.end()].to_owned());
                    ident_prev = ident_match.end();
                }
                if ident_prev < ws_tok.len() {
                    tokens.push(ws_tok[ident_prev..].to_owned());
                }
            }
        }
        Ok(tokens)
    }
}

/// A codes input is the basic input
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct EncodedInput {
    /// The input representation as list of codes
    codes: Vec<u32>,
}

impl Input for EncodedInput {
    /// Generate a name for this input
    #[must_use]
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
    #[must_use]
    fn from(codes: Vec<u32>) -> Self {
        Self::new(codes)
    }
}

impl From<&[u32]> for EncodedInput {
    #[must_use]
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

    /// The codes of this encoded input
    #[must_use]
    pub fn codes(&self) -> &[u32] {
        &self.codes
    }

    /// The codes of this encoded input, mutable
    #[must_use]
    pub fn codes_mut(&mut self) -> &mut Vec<u32> {
        &mut self.codes
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use core::str::from_utf8;

    use crate::inputs::encoded::{
        InputDecoder, InputEncoder, NaiveTokenizer, TokenInputEncoderDecoder,
    };

    #[test]
    fn test_input() {
        let mut t = NaiveTokenizer::default();
        let mut ed = TokenInputEncoderDecoder::new();
        let input = ed
            .encode("/* test */a = 'pippo baudo'; b=c+a\n".as_bytes(), &mut t)
            .unwrap();
        let mut bytes = vec![];
        ed.decode(&input, &mut bytes).unwrap();
        assert_eq!(
            from_utf8(&bytes).unwrap(),
            "a = 'pippo baudo' ; b = c + a ".to_owned()
        );
    }
}
