//! Tokens are what AFL calls extras or dictionaries.
//! They may be inserted as part of mutations during fuzzing.
use alloc::vec::Vec;
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use core::slice::from_raw_parts;
use core::{
    mem::size_of,
    ops::{Add, AddAssign},
    slice::Iter,
};
#[cfg(feature = "std")]
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use hashbrown::HashSet;
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::mutators::str_decode;
use crate::{
    bolts::{rands::Rand, AsSlice},
    inputs::{HasBytesVec, UsesInput},
    mutators::{buffer_self_copy, mutations::buffer_copy, MutationResult, Mutator, Named},
    observers::cmp::{AFLppCmpValuesMetadata, CmpValues, CmpValuesMetadata},
    stages::TaintMetadata,
    state::{HasMaxSize, HasMetadata, HasRand},
    Error,
};

/// A state metadata holding a list of tokens
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct Tokens {
    // We keep a vec and a set, set for faster deduplication, vec for access
    tokens_vec: Vec<Vec<u8>>,
    tokens_set: HashSet<Vec<u8>>,
}

crate::impl_serdeany!(Tokens);

/// The metadata used for token mutators
impl Tokens {
    /// Creates a new tokens metadata (old-skool afl name: `dictornary`)
    #[must_use]
    pub fn new() -> Self {
        Self {
            ..Tokens::default()
        }
    }

    /// Add tokens from a slice of Vecs of bytes
    pub fn add_tokens<IT, V>(&mut self, tokens: IT) -> &mut Self
    where
        IT: IntoIterator<Item = V>,
        V: AsRef<Vec<u8>>,
    {
        for token in tokens {
            self.add_token(token.as_ref());
        }
        self
    }

    /// Build tokens from files
    #[cfg(feature = "std")]
    pub fn add_from_files<IT, P>(mut self, files: IT) -> Result<Self, Error>
    where
        IT: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        for file in files {
            self.add_from_file(file)?;
        }
        Ok(self)
    }

    /// Parse autodict section
    pub fn parse_autodict(&mut self, slice: &[u8], size: usize) {
        let mut head = 0;
        loop {
            if head >= size {
                // Sanity Check
                assert!(head == size);
                break;
            }
            let size = slice[head] as usize;
            head += 1;
            if size > 0 {
                self.add_token(&slice[head..head + size].to_vec());
                log::info!(
                    "Token size: {} content: {:x?}",
                    size,
                    &slice[head..head + size].to_vec()
                );
                head += size;
            }
        }
    }

    /// Create a token section from a start and an end pointer
    /// Reads from an autotokens section, returning the count of new entries read
    ///
    /// # Safety
    /// The caller must ensure that the region between `token_start` and `token_stop`
    /// is a valid region, containing autotokens in the exepcted format.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    pub unsafe fn from_mut_ptrs(
        token_start: *const u8,
        token_stop: *const u8,
    ) -> Result<Self, Error> {
        let mut ret = Self::default();
        if token_start.is_null() || token_stop.is_null() {
            return Ok(Self::new());
        }
        if token_stop < token_start {
            return Err(Error::illegal_argument(format!(
                "Tried to create tokens from illegal section: stop < start ({token_stop:?} < {token_start:?})"
            )));
        }
        let section_size: usize = token_stop.offset_from(token_start).try_into().unwrap();
        // log::info!("size: {}", section_size);
        let slice = from_raw_parts(token_start, section_size);

        // Now we know the beginning and the end of the token section.. let's parse them into tokens
        ret.parse_autodict(slice, section_size);

        Ok(ret)
    }

    /// Creates a new instance from a file
    #[cfg(feature = "std")]
    pub fn from_file<P>(file: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let mut ret = Self::new();
        ret.add_from_file(file)?;
        Ok(ret)
    }

    /// Adds a token to a dictionary, checking it is not a duplicate
    /// Returns `false` if the token was already present and did not get added.
    #[allow(clippy::ptr_arg)]
    pub fn add_token(&mut self, token: &Vec<u8>) -> bool {
        if !self.tokens_set.insert(token.clone()) {
            return false;
        }
        self.tokens_vec.push(token.clone());
        true
    }

    /// Reads a tokens file, returning the count of new entries read
    #[cfg(feature = "std")]
    pub fn add_from_file<P>(&mut self, file: P) -> Result<&mut Self, Error>
    where
        P: AsRef<Path>,
    {
        // log::info!("Loading tokens file {:?} ...", file);

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
            let Some(pos_quote) = line.find('\"') else { return Err(Error::illegal_argument(format!("Illegal line: {line}"))) };
            if line.chars().nth(line.len() - 1) != Some('"') {
                return Err(Error::illegal_argument(format!("Illegal line: {line}")));
            }

            // extract item
            let Some(item) = line.get(pos_quote + 1..line.len() - 1) else { return Err(Error::illegal_argument(format!("Illegal line: {line}"))) };
            if item.is_empty() {
                continue;
            }

            // decode
            let token: Vec<u8> = match str_decode(item) {
                Ok(val) => val,
                Err(_) => {
                    return Err(Error::illegal_argument(format!(
                        "Illegal line (hex decoding): {line}"
                    )))
                }
            };

            // add
            self.add_token(&token);
        }

        Ok(self)
    }

    /// Returns the amount of tokens in this Tokens instance
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens_vec.len()
    }

    /// Returns if this tokens-instance is empty
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens_vec.is_empty()
    }

    /// Gets the tokens stored in this db
    #[must_use]
    pub fn tokens(&self) -> &[Vec<u8>] {
        &self.tokens_vec
    }
}

impl AddAssign for Tokens {
    fn add_assign(&mut self, other: Self) {
        self.add_tokens(&other);
    }
}

impl AddAssign<&[Vec<u8>]> for Tokens {
    fn add_assign(&mut self, other: &[Vec<u8>]) {
        self.add_tokens(other);
    }
}

impl Add<&[Vec<u8>]> for Tokens {
    type Output = Self;
    fn add(self, other: &[Vec<u8>]) -> Self {
        let mut ret = self;
        ret.add_tokens(other);
        ret
    }
}

impl Add for Tokens {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.add(other.tokens_vec.as_slice())
    }
}

impl<IT, V> From<IT> for Tokens
where
    IT: IntoIterator<Item = V>,
    V: AsRef<Vec<u8>>,
{
    fn from(tokens: IT) -> Self {
        let mut ret = Self::default();
        ret.add_tokens(tokens);
        ret
    }
}

impl AsSlice for Tokens {
    type Entry = Vec<u8>;
    fn as_slice(&self) -> &[Vec<u8>] {
        self.tokens()
    }
}

impl Add for &Tokens {
    type Output = Tokens;

    fn add(self, other: Self) -> Tokens {
        let mut ret: Tokens = self.clone();
        ret.add_tokens(other);
        ret
    }
}

impl<'it> IntoIterator for &'it Tokens {
    type Item = <Iter<'it, Vec<u8>> as Iterator>::Item;
    type IntoIter = Iter<'it, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

/// Inserts a random token at a random position in the `Input`.
#[derive(Debug, Default)]
pub struct TokenInsert;

impl<I, S> Mutator<I, S> for TokenInsert
where
    S: HasMetadata + HasRand + HasMaxSize,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let tokens_len = {
            let meta = state.metadata_map().get::<Tokens>();
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

        let meta = state.metadata_map().get::<Tokens>().unwrap();
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

impl Named for TokenInsert {
    fn name(&self) -> &str {
        "TokenInsert"
    }
}

impl TokenInsert {
    /// Create a `TokenInsert` `Mutation`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// A `TokenReplace` [`Mutator`] replaces a random part of the input with one of a range of tokens.
/// From AFL terms, this is called as `Dictionary` mutation (which doesn't really make sense ;) ).
#[derive(Debug, Default)]
pub struct TokenReplace;

impl<I, S> Mutator<I, S> for TokenReplace
where
    S: UsesInput + HasMetadata + HasRand + HasMaxSize,
    I: HasBytesVec,
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
            let meta = state.metadata_map().get::<Tokens>();
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

        let meta = state.metadata_map().get::<Tokens>().unwrap();
        let token = &meta.tokens()[token_idx];
        let mut len = token.len();
        if off + len > size {
            len = size - off;
        }

        buffer_copy(input.bytes_mut(), token, 0, off, len);

        Ok(MutationResult::Mutated)
    }
}

impl Named for TokenReplace {
    fn name(&self) -> &str {
        "TokenReplace"
    }
}

impl TokenReplace {
    /// Creates a new `TokenReplace` struct.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// A `I2SRandReplace` [`Mutator`] replaces a random matching input-2-state comparison operand with the other.
/// It needs a valid [`CmpValuesMetadata`] in the state.
#[derive(Debug, Default)]
pub struct I2SRandReplace;

impl<I, S> Mutator<I, S> for I2SRandReplace
where
    S: UsesInput + HasMetadata + HasRand + HasMaxSize,
    I: HasBytesVec,
{
    #[allow(clippy::too_many_lines)]
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

        let cmps_len = {
            let meta = state.metadata_map().get::<CmpValuesMetadata>();
            if meta.is_none() {
                return Ok(MutationResult::Skipped);
            }
            if meta.unwrap().list.is_empty() {
                return Ok(MutationResult::Skipped);
            }
            meta.unwrap().list.len()
        };
        let idx = state.rand_mut().below(cmps_len as u64) as usize;

        let off = state.rand_mut().below(size as u64) as usize;
        let len = input.bytes().len();
        let bytes = input.bytes_mut();

        let meta = state.metadata_map().get::<CmpValuesMetadata>().unwrap();
        let cmp_values = &meta.list[idx];

        let mut result = MutationResult::Skipped;
        match cmp_values {
            CmpValues::U8(v) => {
                for byte in bytes.iter_mut().take(len).skip(off) {
                    if *byte == v.0 {
                        *byte = v.1;
                        result = MutationResult::Mutated;
                        break;
                    } else if *byte == v.1 {
                        *byte = v.0;
                        result = MutationResult::Mutated;
                        break;
                    }
                }
            }
            CmpValues::U16(v) => {
                if len >= size_of::<u16>() {
                    for i in off..len - (size_of::<u16>() - 1) {
                        let val =
                            u16::from_ne_bytes(bytes[i..i + size_of::<u16>()].try_into().unwrap());
                        if val == v.0 {
                            let new_bytes = v.1.to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = v.0.to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u16>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::U32(v) => {
                if len >= size_of::<u32>() {
                    for i in off..len - (size_of::<u32>() - 1) {
                        let val =
                            u32::from_ne_bytes(bytes[i..i + size_of::<u32>()].try_into().unwrap());
                        if val == v.0 {
                            let new_bytes = v.1.to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = v.0.to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u32>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::U64(v) => {
                if len >= size_of::<u64>() {
                    for i in off..len - (size_of::<u64>() - 1) {
                        let val =
                            u64::from_ne_bytes(bytes[i..i + size_of::<u64>()].try_into().unwrap());
                        if val == v.0 {
                            let new_bytes = v.1.to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.0 {
                            let new_bytes = v.1.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val == v.1 {
                            let new_bytes = v.0.to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        } else if val.swap_bytes() == v.1 {
                            let new_bytes = v.0.swap_bytes().to_ne_bytes();
                            bytes[i..i + size_of::<u64>()].copy_from_slice(&new_bytes);
                            result = MutationResult::Mutated;
                            break;
                        }
                    }
                }
            }
            CmpValues::Bytes(v) => {
                'outer: for i in off..len {
                    let mut size = core::cmp::min(v.0.len(), len - i);
                    while size != 0 {
                        if v.0[0..size] == input.bytes()[i..i + size] {
                            buffer_copy(input.bytes_mut(), &v.1, 0, i, size);
                            result = MutationResult::Mutated;
                            break 'outer;
                        }
                        size -= 1;
                    }
                    size = core::cmp::min(v.1.len(), len - i);
                    while size != 0 {
                        if v.1[0..size] == input.bytes()[i..i + size] {
                            buffer_copy(input.bytes_mut(), &v.0, 0, i, size);
                            result = MutationResult::Mutated;
                            break 'outer;
                        }
                        size -= 1;
                    }
                }
            }
        }

        Ok(result)
    }
}

impl Named for I2SRandReplace {
    fn name(&self) -> &str {
        "I2SRandReplace"
    }
}

impl I2SRandReplace {
    /// Creates a new `I2SRandReplace` struct.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

const CMP_ATTTRIBUTE_IS_EQUAL: u8 = 1;
const CMP_ATTRIBUTE_IS_GREATER: u8 = 2;
const CMP_ATTRIBUTE_IS_LESSER: u8 = 4;
const CMP_ATTRIBUTE_IS_FP: u8 = 8;
const CMP_ATTRIBUTE_IS_FP_MOD: u8 = 16;
const CMP_ATTRIBUTE_IS_INT_MOD: u8 = 32;
const CMP_ATTRIBUTE_IS_TRANSFORM: u8 = 64;

/// AFL++ redqueen mutation
#[derive(Debug, Default)]
pub struct AFLppRedQueen {
    cmp_start_idx: usize,
    cmp_h_start_idx: usize,
    cmp_buf_start_idx: usize,
    taint_idx: usize,
    enable_transform: bool,
    enable_arith: bool,
}

impl AFLppRedQueen {
    #[inline]
    fn swapa(x: u8) -> u8 {
        (x & 0xf8) + ((x & 7) ^ 0x07)
    }

    /// Cmplog Pattern Matching
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::if_not_else)]
    #[allow(clippy::cast_precision_loss)]
    pub fn cmp_extend_encoding(
        &self,
        pattern: u64,
        repl: u64,
        another_pattern: u64,
        changed_val: u64,
        attr: u8,
        another_buf: &[u8],
        buf: &mut [u8], // Unlike AFL++ we change the original buf (it's named buf here)
        buf_idx: usize,
        taint_len: usize,
        input_len: usize,
        hshape: usize,
    ) -> bool {
        // TODO: ascii2num (we need check q->is_ascii (in calibration stage(?)))

        // try Transform
        if self.enable_transform
            && pattern != another_pattern
            && repl == changed_val
            && attr <= CMP_ATTTRIBUTE_IS_EQUAL
        {
            // Try to identify transform magic
            let mut bytes: usize = match hshape {
                0 => 0, // NEVER happen
                1 => 1,
                2 => 2,
                3 | 4 => 4,
                _ => 8,
            };
            // prevent overflow
            bytes = core::cmp::min(bytes, input_len - buf_idx);

            let (b_val, o_b_val, mask): (u64, u64, u64) = match bytes {
                0 => {
                    (0, 0, 0) // cannot happen
                }
                1 => (
                    u64::from(buf[buf_idx]),
                    u64::from(another_buf[buf_idx]),
                    0xff,
                ),
                2 | 3 => (
                    u64::from(u16::from_be_bytes(
                        another_buf[buf_idx..buf_idx + 2].try_into().unwrap(),
                    )),
                    u64::from(u16::from_be_bytes(
                        another_buf[buf_idx..buf_idx + 2].try_into().unwrap(),
                    )),
                    0xffff,
                ),
                4 | 5 | 6 | 7 => (
                    u64::from(u32::from_be_bytes(
                        buf[buf_idx..buf_idx + 4].try_into().unwrap(),
                    )),
                    u64::from(u32::from_be_bytes(
                        another_buf[buf_idx..buf_idx + 4].try_into().unwrap(),
                    )),
                    0xffff_ffff,
                ),
                _ => (
                    u64::from_be_bytes(buf[buf_idx..buf_idx + 8].try_into().unwrap()),
                    u64::from_be_bytes(another_buf[buf_idx..buf_idx + 8].try_into().unwrap()),
                    0xffff_ffff_ffff_ffff,
                ),
            };

            // Try arith
            let diff: i64 = (pattern - b_val) as i64;
            let new_diff: i64 = (another_pattern - o_b_val) as i64;

            if diff == new_diff && diff != 0 {
                let new_repl: u64 = (repl as i64 - diff) as u64;

                let ret = self.cmp_extend_encoding(
                    pattern,
                    new_repl,
                    another_pattern,
                    repl,
                    CMP_ATTRIBUTE_IS_TRANSFORM,
                    another_buf,
                    buf,
                    buf_idx,
                    taint_len,
                    input_len,
                    hshape,
                );
                if ret {
                    return true;
                }
            }

            // Try XOR

            // Shadowing
            let diff: i64 = (pattern ^ b_val) as i64;
            let new_diff: i64 = (another_pattern ^ o_b_val) as i64;

            if diff == new_diff && diff != 0 {
                let new_repl: u64 = (repl as i64 ^ diff) as u64;
                let ret = self.cmp_extend_encoding(
                    pattern,
                    new_repl,
                    another_pattern,
                    repl,
                    CMP_ATTRIBUTE_IS_TRANSFORM,
                    another_buf,
                    buf,
                    buf_idx,
                    taint_len,
                    input_len,
                    hshape,
                );

                if ret {
                    return true;
                }
            }

            // Try Lowercase
            // Shadowing
            let diff = (b_val | 0x2020_2020_2020_2020 & mask) == (pattern & mask);

            let new_diff = (b_val | 0x2020_2020_2020_2020 & mask) == (another_pattern & mask);

            if new_diff && diff {
                let new_repl: u64 = repl & (0x5f5f_5f5f_5f5f_5f5f & mask);
                let ret = self.cmp_extend_encoding(
                    pattern,
                    new_repl,
                    another_pattern,
                    repl,
                    CMP_ATTRIBUTE_IS_TRANSFORM,
                    another_buf,
                    buf,
                    buf_idx,
                    taint_len,
                    input_len,
                    hshape,
                );

                if ret {
                    return true;
                }
            }

            // Try Uppercase
            // Shadowing
            let diff = (b_val | 0x5f5f_5f5f_5f5f_5f5f & mask) == (pattern & mask);

            let o_diff = (b_val | 0x5f5f_5f5f_5f5f_5f5f & mask) == (another_pattern & mask);

            if o_diff && diff {
                let new_repl: u64 = repl & (0x2020_2020_2020_2020 & mask);
                let ret = self.cmp_extend_encoding(
                    pattern,
                    new_repl,
                    another_pattern,
                    repl,
                    CMP_ATTRIBUTE_IS_TRANSFORM,
                    another_buf,
                    buf,
                    buf_idx,
                    taint_len,
                    input_len,
                    hshape,
                );

                if ret {
                    return true;
                }
            }
        }

        let its_len = core::cmp::min(input_len - buf_idx, taint_len);

        // Try pattern matching
        // println!("Pattern match");
        match hshape {
            0 => (), // NEVER HAPPEN, Do nothing
            1 => {
                // 1 byte pattern match
                let buf_8 = buf[buf_idx];
                let another_buf_8 = another_buf[buf_idx];
                if buf_8 == pattern as u8 && another_buf_8 == another_pattern as u8 {
                    buf[buf_idx] = repl as u8;
                    return true;
                }
            }
            2 | 3 => {
                if its_len >= 2 {
                    let buf_16 = u16::from_be_bytes(buf[buf_idx..buf_idx + 2].try_into().unwrap());
                    let another_buf_16 =
                        u16::from_be_bytes(another_buf[buf_idx..buf_idx + 2].try_into().unwrap());

                    if buf_16 == pattern as u16 && another_buf_16 == another_pattern as u16 {
                        buf[buf_idx] = (repl & 0xff) as u8;
                        buf[buf_idx + 1] = (repl >> 8 & 0xff) as u8;
                        return true;
                    }
                }
            }
            4 | 5 | 6 | 7 => {
                if its_len >= 4 {
                    let buf_32 = u32::from_be_bytes(buf[buf_idx..buf_idx + 4].try_into().unwrap());
                    let another_buf_32 =
                        u32::from_be_bytes(another_buf[buf_idx..buf_idx + 4].try_into().unwrap());
                    // println!("buf: {buf_32} {another_buf_32} {pattern} {another_pattern}");
                    if buf_32 == pattern as u32 && another_buf_32 == another_pattern as u32 {
                        // println!("Matched!");
                        buf[buf_idx] = (repl & 0xff) as u8;
                        buf[buf_idx + 1] = (repl >> 8 & 0xff) as u8;
                        buf[buf_idx + 2] = (repl >> 16 & 0xff) as u8;
                        buf[buf_idx + 3] = (repl >> 24 & 0xff) as u8;

                        return true;
                    }
                }
            }
            _ => {
                if its_len >= 8 {
                    let buf_64 = u64::from_be_bytes(buf[buf_idx..buf_idx + 8].try_into().unwrap());
                    let another_buf_64 =
                        u64::from_be_bytes(another_buf[buf_idx..buf_idx + 8].try_into().unwrap());

                    if buf_64 == pattern && another_buf_64 == another_pattern {
                        buf[buf_idx] = (repl & 0xff) as u8;
                        buf[buf_idx + 1] = (repl >> 8 & 0xff) as u8;
                        buf[buf_idx + 2] = (repl >> 16 & 0xff) as u8;
                        buf[buf_idx + 3] = (repl >> 24 & 0xff) as u8;
                        buf[buf_idx + 4] = (repl >> 32 & 0xff) as u8;
                        buf[buf_idx + 5] = (repl >> 32 & 0xff) as u8;
                        buf[buf_idx + 6] = (repl >> 40 & 0xff) as u8;
                        buf[buf_idx + 7] = (repl >> 48 & 0xff) as u8;
                        return true;
                    }
                }
            }
        }

        // Try arith
        if self.enable_arith || attr != CMP_ATTRIBUTE_IS_TRANSFORM {
            if (attr & (CMP_ATTRIBUTE_IS_GREATER | CMP_ATTRIBUTE_IS_LESSER)) == 0 || hshape < 4 {
                return false;
            }

            // Transform >= to < and <= to >
            let attr = if (attr & CMP_ATTTRIBUTE_IS_EQUAL) != 0
                && (attr & (CMP_ATTRIBUTE_IS_GREATER | CMP_ATTRIBUTE_IS_LESSER)) != 0
            {
                if attr & CMP_ATTRIBUTE_IS_GREATER != 0 {
                    attr + 2
                } else {
                    attr - 2
                }
            } else {
                attr
            };

            // FP
            if (CMP_ATTRIBUTE_IS_FP..CMP_ATTRIBUTE_IS_FP_MOD).contains(&attr) {
                let repl_new: u64;

                if attr & CMP_ATTRIBUTE_IS_GREATER != 0 {
                    if hshape == 4 && its_len >= 4 {
                        let mut g = repl as f32;
                        g += 1.0;
                        repl_new = u64::from(g as u32);
                    } else if hshape == 8 && its_len >= 8 {
                        let mut g = repl as f64;
                        g += 1.0;
                        repl_new = g as u64;
                    } else {
                        return false;
                    }

                    let ret = self.cmp_extend_encoding(
                        pattern,
                        repl,
                        another_pattern,
                        repl_new,
                        CMP_ATTRIBUTE_IS_FP_MOD,
                        another_buf,
                        buf,
                        buf_idx,
                        taint_len,
                        input_len,
                        hshape,
                    );
                    if ret {
                        return true;
                    }
                } else {
                    if hshape == 4 && its_len >= 4 {
                        let mut g = repl as f32;
                        g -= 1.0;
                        repl_new = u64::from(g as u32);
                    } else if hshape == 8 && its_len >= 8 {
                        let mut g = repl as f64;
                        g -= 1.0;
                        repl_new = g as u64;
                    } else {
                        return false;
                    }

                    let ret = self.cmp_extend_encoding(
                        pattern,
                        repl,
                        another_pattern,
                        repl_new,
                        CMP_ATTRIBUTE_IS_FP_MOD,
                        another_buf,
                        buf,
                        buf_idx,
                        taint_len,
                        input_len,
                        hshape,
                    );
                    if ret {
                        return true;
                    }
                }
            } else if attr < CMP_ATTRIBUTE_IS_FP {
                if attr & CMP_ATTRIBUTE_IS_GREATER != 0 {
                    let repl_new = repl + 1;

                    let ret = self.cmp_extend_encoding(
                        pattern,
                        repl,
                        another_pattern,
                        repl_new,
                        CMP_ATTRIBUTE_IS_INT_MOD,
                        another_buf,
                        buf,
                        buf_idx,
                        taint_len,
                        input_len,
                        hshape,
                    );

                    if ret {
                        return true;
                    }
                } else {
                    let repl_new = repl - 1;

                    let ret = self.cmp_extend_encoding(
                        pattern,
                        repl,
                        another_pattern,
                        repl_new,
                        CMP_ATTRIBUTE_IS_INT_MOD,
                        another_buf,
                        buf,
                        buf_idx,
                        taint_len,
                        input_len,
                        hshape,
                    );

                    if ret {
                        return true;
                    }
                }
            } else {
                return false;
            }
        }

        false
    }

    /// rtn part from AFL++
    #[allow(clippy::too_many_arguments)]
    pub fn rtn_extend_encoding(
        &self,
        pattern: &[u8],
        repl: &[u8],
        o_pattern: &[u8],
        _changed_val: &[u8],
        o_buf: &[u8],
        buf: &mut [u8],
        buf_idx: usize,
        taint_len: usize,
        input_len: usize,
        hshape: usize,
    ) -> bool {
        let l0 = pattern.len();
        let ol0 = repl.len();
        // let l1 = o_pattern.len();
        // let ol1 = changed_val.len();

        let lmax = core::cmp::max(l0, ol0);
        let its_len = core::cmp::min(
            core::cmp::min(input_len - buf_idx, taint_len),
            core::cmp::min(lmax, hshape),
        );

        // TODO: Match before (This: https://github.com/AFLplusplus/AFLplusplus/blob/ea14f3fd40e32234989043a525e3853fcb33c1b6/src/afl-fuzz-redqueen.c#L2047)
        let mut copy_len = 0;
        for i in 0..its_len {
            if pattern[i] != buf[buf_idx + i] && o_pattern[i] != o_buf[buf_idx + i] {
                break;
            }
            copy_len += 1;
        }

        if copy_len > 0 {
            buffer_copy(buf, repl, 0, buf_idx, copy_len);
            true
        } else {
            false
        }

        // TODO: Transform (This: https://github.com/AFLplusplus/AFLplusplus/blob/stable/src/afl-fuzz-redqueen.c#L2089)
        // It's hard to implement this naively
        // because AFL++ redqueen does not check any pattern, but it calls its_fuzz() instead.
        // we can't execute the harness inside a mutator

        // Direct matching
    }
}

impl<I, S> Mutator<I, S> for AFLppRedQueen
where
    S: UsesInput + HasMetadata + HasRand + HasMaxSize,
    I: HasBytesVec,
{
    #[allow(clippy::needless_range_loop)]
    #[allow(clippy::too_many_lines)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // TODO
        // add autotokens (https://github.com/AFLplusplus/AFLplusplus/blob/3881ccd0b7520f67fd0b34f010443dc249cbc8f1/src/afl-fuzz-redqueen.c#L1903)
        // handle 128-bits logs

        let size = input.bytes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }

        let (cmp_len, cmp_meta, taint_meta) = {
            let cmp_meta = state.metadata_map().get::<AFLppCmpValuesMetadata>();
            let taint_meta = state.metadata_map().get::<TaintMetadata>();
            if cmp_meta.is_none() || taint_meta.is_none() {
                return Ok(MutationResult::Skipped);
            }

            let cmp_len = cmp_meta.unwrap().headers().len();
            if cmp_len == 0 {
                return Ok(MutationResult::Skipped);
            }
            (cmp_len, cmp_meta.unwrap(), taint_meta.unwrap())
        };

        // These idxes must saved in this mutator itself!
        let (cmp_start_idx, cmp_h_start_idx, cmp_buf_start_idx, mut taint_idx) = if stage_idx == 0 {
            (0, 0, 0, 0)
        } else {
            (
                self.cmp_start_idx,
                self.cmp_h_start_idx,
                self.cmp_buf_start_idx,
                self.taint_idx,
            )
        };

        let orig_cmpvals = cmp_meta.orig_cmpvals();
        let new_cmpvals = cmp_meta.new_cmpvals();
        let headers = cmp_meta.headers();
        let input_len = input.bytes().len();
        let new_bytes = taint_meta.input_vec();
        let orig_bytes = input.bytes_mut();
        // TODO: Swap this.
        let taint = taint_meta.ranges();
        // println!("orig: {:#?} new: {:#?}", orig_cmpvals, new_cmpvals);
        for cmp_idx in cmp_start_idx..cmp_len {
            let (w_idx, header) = headers[cmp_idx];

            if orig_cmpvals.get(&w_idx).is_none() || new_cmpvals.get(&w_idx).is_none() {
                // These two should have same boolean value

                // so there's nothing interesting at cmp_idx, then just skip!
                continue;
            }

            let orig_val = orig_cmpvals.get(&w_idx).unwrap();
            let new_val = new_cmpvals.get(&w_idx).unwrap();

            let logged = core::cmp::min(orig_val.len(), new_val.len());

            for cmp_h_idx in cmp_h_start_idx..logged {
                let mut skip_opt = false;
                for prev_idx in 0..cmp_h_idx {
                    if new_val[prev_idx] == new_val[cmp_h_idx] {
                        skip_opt = true;
                    }
                }
                // Opt not in the paper
                if skip_opt {
                    continue;
                }

                for cmp_buf_idx in cmp_buf_start_idx..input_len {
                    let taint_len = match taint.get(taint_idx) {
                        Some(t) => {
                            if cmp_buf_idx < t.start {
                                input_len - cmp_buf_idx
                            } else {
                                // if cmp_buf_idx == t.end go to next range
                                if cmp_buf_idx == t.end {
                                    taint_idx += 1;
                                }

                                // Here cmp_buf_idx >= t.start
                                t.end - cmp_buf_idx
                            }
                        }
                        None => input_len - cmp_buf_idx,
                    };

                    let hshape = (header.shape() + 1) as usize;
                    let mut matched = false;
                    match (&orig_val[cmp_h_idx], &new_val[cmp_h_idx]) {
                        (CmpValues::U8(orig), CmpValues::U8(new)) => {
                            let (orig_v0, orig_v1, new_v0, new_v1) = (orig.0, orig.1, new.0, new.1);

                            let attribute = header.attribute() as u8;
                            if new_v0 != orig_v0 && orig_v0 != orig_v1 {
                                // Compare v0 against v1
                                if self.cmp_extend_encoding(
                                    orig_v0.into(),
                                    orig_v1.into(),
                                    new_v0.into(),
                                    new_v1.into(),
                                    attribute,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }

                                // Swapped
                                if self.cmp_extend_encoding(
                                    orig_v0.swap_bytes().into(),
                                    orig_v1.swap_bytes().into(),
                                    new_v0.swap_bytes().into(),
                                    new_v1.swap_bytes().into(),
                                    attribute,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }

                            if new_v1 != orig_v1 && orig_v0 != orig_v1 {
                                // Compare v1 against v0
                                if self.cmp_extend_encoding(
                                    orig_v1.into(),
                                    orig_v0.into(),
                                    new_v1.into(),
                                    new_v0.into(),
                                    Self::swapa(attribute),
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }

                                // Swapped
                                if self.cmp_extend_encoding(
                                    orig_v1.swap_bytes().into(),
                                    orig_v0.swap_bytes().into(),
                                    new_v1.swap_bytes().into(),
                                    new_v0.swap_bytes().into(),
                                    Self::swapa(attribute),
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }
                        }
                        (CmpValues::U16(orig), CmpValues::U16(new)) => {
                            let (orig_v0, orig_v1, new_v0, new_v1) = (orig.0, orig.1, new.0, new.1);
                            let attribute: u8 = header.attribute() as u8;
                            if new_v0 != orig_v0 && orig_v0 != orig_v1 {
                                // Compare v0 against v1
                                if self.cmp_extend_encoding(
                                    orig_v0.into(),
                                    orig_v1.into(),
                                    new_v0.into(),
                                    new_v1.into(),
                                    attribute,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }

                                // Swapped
                                // Compare v0 against v1
                                if self.cmp_extend_encoding(
                                    orig_v0.swap_bytes().into(),
                                    orig_v1.swap_bytes().into(),
                                    new_v0.swap_bytes().into(),
                                    new_v1.swap_bytes().into(),
                                    attribute,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }

                            if new_v1 != orig_v1 && orig_v0 != orig_v1 {
                                // Compare v1 against v0
                                if self.cmp_extend_encoding(
                                    orig_v1.into(),
                                    orig_v0.into(),
                                    new_v1.into(),
                                    new_v0.into(),
                                    Self::swapa(attribute),
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }

                                // Swapped
                                if self.cmp_extend_encoding(
                                    orig_v1.swap_bytes().into(),
                                    orig_v0.swap_bytes().into(),
                                    new_v1.swap_bytes().into(),
                                    new_v0.swap_bytes().into(),
                                    Self::swapa(attribute),
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }
                        }
                        (CmpValues::U32(orig), CmpValues::U32(new)) => {
                            let (orig_v0, orig_v1, new_v0, new_v1) = (orig.0, orig.1, new.0, new.1);
                            let attribute = header.attribute() as u8;
                            if new_v0 != orig_v0 && orig_v0 != orig_v1 {
                                // Compare v0 against v1
                                if self.cmp_extend_encoding(
                                    orig_v0.into(),
                                    orig_v1.into(),
                                    new_v0.into(),
                                    new_v1.into(),
                                    attribute,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }

                                // swapped
                                // Compare v0 against v1
                                if self.cmp_extend_encoding(
                                    orig_v0.swap_bytes().into(),
                                    orig_v1.swap_bytes().into(),
                                    new_v0.swap_bytes().into(),
                                    new_v1.swap_bytes().into(),
                                    attribute,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }

                            if new_v1 != orig_v1 && orig_v0 != orig_v1 {
                                // Compare v1 against v0
                                if self.cmp_extend_encoding(
                                    orig_v1.into(),
                                    orig_v0.into(),
                                    new_v1.into(),
                                    new_v0.into(),
                                    Self::swapa(attribute),
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }

                                // Swapped
                                // Compare v1 against v0
                                if self.cmp_extend_encoding(
                                    orig_v1.swap_bytes().into(),
                                    orig_v0.swap_bytes().into(),
                                    new_v1.swap_bytes().into(),
                                    new_v0.swap_bytes().into(),
                                    Self::swapa(attribute),
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }
                        }
                        (CmpValues::U64(orig), CmpValues::U64(new)) => {
                            let (orig_v0, orig_v1, new_v0, new_v1) = (orig.0, orig.1, new.0, new.1);
                            let attribute = header.attribute() as u8;
                            if new_v0 != orig_v0 && orig_v0 != orig_v1 {
                                // Compare v0 against v1
                                if self.cmp_extend_encoding(
                                    orig_v0,
                                    orig_v1,
                                    new_v0,
                                    new_v1,
                                    attribute,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }

                                // Swapped
                                // Compare v0 against v1
                                if self.cmp_extend_encoding(
                                    orig_v0.swap_bytes(),
                                    orig_v1.swap_bytes(),
                                    new_v0.swap_bytes(),
                                    new_v1.swap_bytes(),
                                    attribute,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }

                            if new_v1 != orig_v1 && orig_v0 != orig_v1 {
                                // Compare v1 against v0
                                if self.cmp_extend_encoding(
                                    orig_v1,
                                    orig_v0,
                                    new_v1,
                                    new_v0,
                                    Self::swapa(attribute),
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }

                                // Swapped
                                // Compare v1 against v0
                                if self.cmp_extend_encoding(
                                    orig_v1.swap_bytes(),
                                    orig_v0.swap_bytes(),
                                    new_v1.swap_bytes(),
                                    new_v0.swap_bytes(),
                                    Self::swapa(attribute),
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }
                        }
                        (CmpValues::Bytes(orig), CmpValues::Bytes(new)) => {
                            let (orig_v0, orig_v1, new_v0, new_v1) =
                                (&orig.0, &orig.1, &new.0, &new.1);
                            // let attribute = header.attribute() as u8;
                            if new_v0 != orig_v0 && orig_v0 != orig_v1 {
                                // Compare v0 against v1
                                if self.rtn_extend_encoding(
                                    orig_v0,
                                    orig_v1,
                                    new_v0,
                                    new_v1,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }

                            if new_v1 != orig_v1 && orig_v0 != orig_v1 {
                                // Compare v1 against v0
                                if self.rtn_extend_encoding(
                                    orig_v1,
                                    orig_v0,
                                    new_v1,
                                    new_v0,
                                    new_bytes,
                                    orig_bytes,
                                    cmp_buf_idx,
                                    taint_len,
                                    input_len,
                                    hshape,
                                ) {
                                    matched = true;
                                }
                            }
                        }
                        (_, _) => {
                            // It shouldn't have different shape!
                        }
                    }

                    if matched {
                        // before returning the result
                        // save indexes
                        self.cmp_start_idx = cmp_start_idx;
                        self.cmp_h_start_idx = cmp_h_start_idx;
                        self.cmp_buf_start_idx = cmp_buf_start_idx + 1; // next
                        self.taint_idx = taint_idx;

                        return Ok(MutationResult::Mutated);
                    }
                    // if no match then go to next round
                }
            }
        }

        Ok(MutationResult::Skipped)
    }
}

impl Named for AFLppRedQueen {
    fn name(&self) -> &str {
        "AFLppRedQueen"
    }
}

impl AFLppRedQueen {
    /// Create a new `AFLppRedQueen` Mutator
    #[must_use]
    pub fn new() -> Self {
        Self {
            cmp_start_idx: 0,
            cmp_h_start_idx: 0,
            cmp_buf_start_idx: 0,
            taint_idx: 0,
            enable_transform: false,
            enable_arith: false,
        }
    }

    /// Constructor with cmplog options
    #[must_use]
    pub fn with_cmplog_options(transform: bool, arith: bool) -> Self {
        Self {
            cmp_start_idx: 0,
            cmp_h_start_idx: 0,
            cmp_buf_start_idx: 0,
            taint_idx: 0,
            enable_transform: transform,
            enable_arith: arith,
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
        let _res = fs::remove_file("test.tkns");
        let data = r###"
# comment
token1@123="AAA"
token1="A\x41A"
"A\AA"
token2="B"
        "###;
        fs::write("test.tkns", data).expect("Unable to write test.tkns");
        let tokens = Tokens::from_file("test.tkns").unwrap();
        log::info!("Token file entries: {:?}", tokens.tokens());
        assert_eq!(tokens.tokens().len(), 2);
        let _res = fs::remove_file("test.tkns");
    }
}
