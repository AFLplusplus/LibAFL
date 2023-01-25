//! The `EncodedInput` is the "normal" input, a map of codes, that can be sent directly to the client
//! (As opposed to other, more abstract, inputs, like an Grammar-Based AST Input)
//! See also [the paper on token-level fuzzing](https://www.usenix.org/system/files/sec21-salls.pdf)

use alloc::{
    borrow::ToOwned,
    rc::Rc,
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "std")]
use core::{cell::RefCell, convert::From, hash::Hasher};

use ahash::AHasher;
use hashbrown::HashMap;
#[cfg(feature = "std")]
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{
        rands::{Rand, StdRand},
        HasLen,
    },
    inputs::Input,
    Error,
};

#[derive(Clone, Copy, Debug, PartialEq)]
/// Enum to specify the time of encoding for [`TokenInputEncoderDecoder::set_encoding_type`]
pub enum TokenizationKind {
    /// NoWhitespace - do not encode whitespace, every token will be separated by a space
    NoWhitespace,
    /// WithWhitespace - also encode whitespace (continuously)
    WithWhitespace,
}

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
    fn decode(&mut self, input: &EncodedInput, bytes: &mut Vec<u8>) -> Result<(), Error>;
    /// Repair mutated input in [`TokenizationKind::WithWhitespace`] form before decoding
    fn repair(&mut self, input: &mut EncodedInput);
}

/// Tokenizer is a trait that can tokenize bytes into a [`Vec`] of tokens
pub trait Tokenizer {
    /// Tokenize the given bytes
    fn tokenize(&self, bytes: &[u8], encoding_type: TokenizationKind)
        -> Result<Vec<String>, Error>;
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
    // Which type of encoding
    encoding_type: TokenizationKind,
    // This is for TokenizationKind::WithWhitespace
    max_whitespace_id: u32,
}

impl<T> InputEncoder<T> for TokenInputEncoderDecoder
where
    T: Tokenizer,
{
    fn encode(&mut self, bytes: &[u8], tokenizer: &mut T) -> Result<EncodedInput, Error> {
        let tokens = tokenizer.tokenize(bytes, self.encoding_type)?;
        let mut codes: Vec<u32> = Vec::with_capacity(tokens.len());
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
    fn decode(&mut self, input: &EncodedInput, bytes: &mut Vec<u8>) -> Result<(), Error> {
        let codes = &input.codes;
        // Decode the input vector to actual bytes
        for id in codes {
            let tok = self
                .id_table
                .get(&(id % self.next_id))
                .ok_or_else(|| Error::illegal_state(format!("Id {id} not in the decoder table")))?;
            bytes.extend_from_slice(tok.as_bytes());
            if self.encoding_type == TokenizationKind::NoWhitespace {
                bytes.push(b' ');
            }
        }
        Ok(())
    }
    fn repair(&mut self, input: &mut EncodedInput) {
        let codes = &mut input.codes;
        if self.encoding_type == TokenizationKind::WithWhitespace {
            // If we encode whitespace, mutations can f*ck up validity
            // by removing whitespace or single char tokens like `+` to
            // create illegal entries like Variable1"String". We need to
            // fix such entries. So wherever we have two tokens that have
            // a length larger than 1 and are not whitespace, we randomly
            // insert whitespace or a single byte token from our token vec.
            // We do this randomly because this enhances the overall
            // mutation quality.
            let mut positions: Vec<usize> = vec![];
            let mut prev_len = 0;

            // not using for (p, <i>) in codes because it makes it harder to understand
            #[allow(clippy::needless_range_loop)]
            for pos in 0..codes.len() {
                let tok = self.id_table.get(&(codes[pos] % self.next_id)).unwrap();
                let len = tok.len();
                if prev_len > 1 && len > 1 {
                    positions.push(pos);
                }
                prev_len = len;
            }

            if !positions.is_empty() {
                // We need to repair the input
                #[allow(clippy::cast_lossless)]
                let mut rand = StdRand::with_seed(
                    ((positions.len() as u64) << 24)
                        + ((codes.len() as u64) << 16)
                        + ((codes[0] as u64) << 8)
                        + positions[0] as u64,
                );

                // we have to walk backwards otherwise the positions become wrong
                for pos in positions.iter().rev() {
                    let mut r: u32;
                    loop {
                        r = rand.below(u64::from(self.next_id)) as u32;
                        if r < self.max_whitespace_id {
                            break;
                        }
                        if self.id_table.get(&(r % self.next_id)).unwrap().len() == 1 {
                            break;
                        }
                    }
                    codes.insert(*pos, r);
                }
            }
        }
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
            max_whitespace_id: 0,
            encoding_type: TokenizationKind::NoWhitespace,
        }
    }
    /// Sets an encoding type of type [`TokenizationKind`]
    pub fn set_encoding_type(&mut self, enc_type: TokenizationKind) -> Result<(), Error> {
        // This can only be set until the first tokenization has occurred!
        if self.next_id == 0 {
            if enc_type == TokenizationKind::WithWhitespace {
                // we preset whitespace variations to be able to easily find
                // these for later, this is what max_whitespace_id is for.
                // This does not need to be a complete list, just the most common
                // ones.
                self.token_table.insert(" ".to_string(), self.next_id);
                self.id_table.insert(self.next_id, " ".to_string());
                self.next_id += 1;
                self.token_table.insert("\t".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\t".to_string());
                self.next_id += 1;
                self.token_table.insert("\n".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\n".to_string());
                self.next_id += 1;
                self.token_table.insert("\r\n".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\r\n".to_string());
                self.next_id += 1;
                self.token_table.insert("  ".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "  ".to_string());
                self.next_id += 1;
                self.token_table.insert("\t\t".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\t\t".to_string());
                self.next_id += 1;
                self.token_table.insert("\n\n".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\n\n".to_string());
                self.next_id += 1;
                self.token_table
                    .insert("\r\n\r\n".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\r\n\r\n".to_string());
                self.next_id += 1;
                self.token_table.insert("    ".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "    ".to_string());
                self.next_id += 1;
                self.token_table
                    .insert("\t\t\t\t".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\t\t\t\t".to_string());
                self.next_id += 1;
                self.token_table
                    .insert("\n\n\n\n".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\n\n\n\n".to_string());
                self.next_id += 1;
                self.token_table
                    .insert("\r\n\r\n".to_string(), self.next_id);
                self.id_table
                    .insert(self.next_id, "\r\n\r\n\r\n\r\n".to_string());
                self.next_id += 1;
                self.max_whitespace_id = self.next_id;

                // To be able to also insert single quote types during mutation
                // we also add these
                self.token_table.insert("\"".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "\"".to_string());
                self.next_id += 1;
                self.token_table.insert("'".to_string(), self.next_id);
                self.id_table.insert(self.next_id, "'".to_string());
                self.next_id += 1;
            }
            self.encoding_type = enc_type;
        } else {
            return Err(Error::illegal_state(
                "An input was already encoded, set_encoding_type() must be called prior!",
            ));
        }
        Ok(())
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
    /// replacement character regex
    replace_re: Regex,
}

#[cfg(feature = "std")]
impl NaiveTokenizer {
    /// Creates a new [`NaiveTokenizer`]
    #[must_use]
    pub fn new(ident_re: Regex, comment_re: Regex, string_re: Regex, replace_re: Regex) -> Self {
        Self {
            ident_re,
            comment_re,
            string_re,
            replace_re,
        }
    }
}

#[cfg(feature = "std")]
impl Default for NaiveTokenizer {
    fn default() -> Self {
        Self {
            // Generic identifier regex
            ident_re: Regex::new("[A-Za-z0-9_$]+").unwrap(),
            // C++ style /* ... */ comments, no // because is bad for XML and other
            comment_re: Regex::new(r"(/\*[^*]*\*/)").unwrap(),
            // " and ' string regex
            string_re: Regex::new("\"(\\\\|\\\\\"|[^\"])*\"|'(\\\\|\\\\'|[^'])*'").unwrap(),
            // replacement character regex
            replace_re: Regex::new("[\u{FFFD}]").unwrap(),
        }
    }
}

#[cfg(feature = "std")]
impl Tokenizer for NaiveTokenizer {
    #[allow(clippy::too_many_lines)]
    fn tokenize(
        &self,
        bytes: &[u8],
        encoding_type: TokenizationKind,
    ) -> Result<Vec<String>, Error> {
        let mut tokens = vec![];
        let stringer = String::from_utf8_lossy(bytes).into_owned(); //.unwrap();
        let string: &str = &stringer;
        let string = self.comment_re.replace_all(string, "").to_string();
        let string = self.replace_re.replace_all(&string, "").to_string();
        let mut str_prev = 0;
        for str_match in self.string_re.find_iter(&string) {
            if str_match.start() > str_prev {
                if encoding_type == TokenizationKind::WithWhitespace {
                    let mut ident_prev = 0;
                    let substring = string[str_prev..str_match.start()].to_owned();
                    for ident_match in self.ident_re.find_iter(&substring) {
                        if ident_match.start() > ident_prev {
                            let mut ws_start = 0;
                            for cnt in ident_prev..ident_match.start() {
                                if substring.chars().nth(cnt).unwrap_or('x').is_whitespace() {
                                    if ws_start == 0 {
                                        ws_start = cnt;
                                    }
                                } else {
                                    if ws_start > 0 {
                                        tokens.push(substring[ws_start..cnt].to_owned());
                                        ws_start = 0;
                                    }
                                    tokens.push(substring[cnt..=cnt].to_owned());
                                }
                            }
                            if ws_start > 0 {
                                tokens.push(substring[ws_start..ident_match.start()].to_owned());
                            }
                        }
                        tokens.push(substring[ident_match.start()..ident_match.end()].to_owned());
                        ident_prev = ident_match.end();
                    }
                    if ident_prev < substring.len() {
                        for cnt in ident_prev..substring.len() {
                            tokens.push(substring[cnt..=cnt].to_owned());
                        }
                    }
                } else {
                    // it is better to use .split(' \t') to keep EOLs, but it is currently unstable
                    for ws_tok in string[str_prev..str_match.start()].split_whitespace() {
                        let mut ident_prev = 0;
                        for ident_match in self.ident_re.find_iter(ws_tok) {
                            if ident_match.start() > ident_prev {
                                for cnt in ident_prev..ident_match.start() {
                                    tokens.push(ws_tok[cnt..=cnt].to_owned());
                                }
                            }
                            tokens.push(ws_tok[ident_match.start()..ident_match.end()].to_owned());
                            ident_prev = ident_match.end();
                        }
                        if ident_prev < ws_tok.len() {
                            for cnt in ident_prev..ws_tok.len() {
                                tokens.push(ws_tok[cnt..=cnt].to_owned());
                            }
                        }
                    }
                }
            }
            tokens.push(string[str_match.start()..str_match.end()].to_owned());
            str_prev = str_match.end();
        }
        if str_prev < string.len() {
            if encoding_type == TokenizationKind::WithWhitespace {
                let mut ident_prev = 0;
                let substring = string[str_prev..].to_owned();
                for ident_match in self.ident_re.find_iter(&substring) {
                    if ident_match.start() > ident_prev {
                        let mut ws_start = 0;
                        for cnt in ident_prev..ident_match.start() {
                            if substring.chars().nth(cnt).unwrap_or('x').is_whitespace() {
                                if ws_start == 0 {
                                    ws_start = cnt;
                                }
                            } else {
                                if ws_start > 0 {
                                    tokens.push(substring[ws_start..cnt].to_owned());
                                    ws_start = 0;
                                }
                                tokens.push(substring[cnt..=cnt].to_owned());
                            }
                        }
                        if ws_start > 0 {
                            tokens.push(substring[ws_start..ident_match.start()].to_owned());
                        }
                    }
                    tokens.push(substring[ident_match.start()..ident_match.end()].to_owned());
                    ident_prev = ident_match.end();
                }
                if ident_prev < substring.len() {
                    for cnt in ident_prev..substring.len() {
                        tokens.push(substring[cnt..=cnt].to_owned());
                    }
                }
            } else {
                // it is better to use .split(' \t') to keep EOLs, but it is currently unstable
                for ws_tok in string[str_prev..].split_whitespace() {
                    let mut ident_prev = 0;
                    for ident_match in self.ident_re.find_iter(ws_tok) {
                        if ident_match.start() > ident_prev {
                            for cnt in ident_prev..ident_match.start() {
                                tokens.push(ws_tok[cnt..=cnt].to_owned());
                            }
                        }
                        tokens.push(ws_tok[ident_match.start()..ident_match.end()].to_owned());
                        ident_prev = ident_match.end();
                    }
                    if ident_prev < ws_tok.len() {
                        for cnt in ident_prev..ws_tok.len() {
                            tokens.push(ws_tok[cnt..=cnt].to_owned());
                        }
                    }
                }
            }
        }
        Ok(tokens)
    }
}

/// A `codes` input is the basic input
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
    use alloc::string::ToString;
    use core::str::from_utf8;

    use crate::{
        bolts::rands::{Rand, StdRand},
        inputs::encoded::{
            InputDecoder, InputEncoder, NaiveTokenizer, TokenInputEncoderDecoder, TokenizationKind,
        },
    };

    #[test]
    fn test_input() {
        let string = "/* test */a = 'pippo baudo';   b=c+a\n";
        let verify1 = "a = 'pippo baudo' ; b = c + a ";
        let verify2 = "a = 'pippo baudo';   b=c+a\n";
        let mut t = NaiveTokenizer::default();
        let mut ed = TokenInputEncoderDecoder::new();
        let mut input = ed.encode(string.to_string().as_bytes(), &mut t).unwrap();
        let mut bytes = vec![];
        ed.decode(&input, &mut bytes).unwrap();
        assert_eq!(from_utf8(&bytes).unwrap(), verify1);
        t = NaiveTokenizer::default();
        ed = TokenInputEncoderDecoder::new();
        ed.set_encoding_type(TokenizationKind::WithWhitespace)
            .unwrap();
        input = ed.encode(string.to_string().as_bytes(), &mut t).unwrap();
        bytes = vec![];
        /*
        for i in 0..input.codes.len() {
          println!("Code {i}: {:?}", input.codes[i]);
        }
        */
        ed.decode(&input, &mut bytes).unwrap();
        assert_eq!(from_utf8(&bytes).unwrap(), verify2);

        let val = StdRand::default().choose(input.codes_mut());
        *val = val.wrapping_sub(1);

        bytes.clear();
        let mut bytes2 = vec![];

        ed.decode(&input, &mut bytes).unwrap();
        ed.decode(&input, &mut bytes2).unwrap();

        assert_eq!(bytes, bytes2);

        /*
        for id in 0..ed.next_id {
            let tok = ed
                .id_table
                .get(&(id % ed.next_id));
            assert_eq!(from_utf8(&bytes).unwrap(), verify2);
            println!("Token {id}: {:?}", tok.unwrap());
        }
        */
    }
}
