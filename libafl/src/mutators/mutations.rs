//! A wide variety of mutations used during fuzzing.

use alloc::{borrow::ToOwned, vec::Vec};
use core::{
    cmp::{max, min},
    mem::size_of,
};

use crate::{
    bolts::{rands::Rand, tuples::Named},
    corpus::Corpus,
    inputs::HasBytesVec,
    mutators::{MutationResult, Mutator},
    random_corpus_id,
    state::{HasCorpus, HasMaxSize, HasRand},
    Error,
};

/// Mem move in the own vec
#[inline]
pub fn buffer_self_copy<T>(data: &mut [T], from: usize, to: usize, len: usize) {
    debug_assert!(!data.is_empty());
    debug_assert!(from + len <= data.len());
    debug_assert!(to + len <= data.len());
    if len != 0 && from != to {
        let ptr = data.as_mut_ptr();
        unsafe {
            core::ptr::copy(ptr.add(from), ptr.add(to), len);
        }
    }
}

/// Mem move between vecs
#[inline]
pub fn buffer_copy<T>(dst: &mut [T], src: &[T], from: usize, to: usize, len: usize) {
    debug_assert!(!dst.is_empty());
    debug_assert!(!src.is_empty());
    debug_assert!(from + len <= src.len());
    debug_assert!(to + len <= dst.len());
    let dst_ptr = dst.as_mut_ptr();
    let src_ptr = src.as_ptr();
    if len != 0 {
        unsafe {
            core::ptr::copy(src_ptr.add(from), dst_ptr.add(to), len);
        }
    }
}

/// A simple way to set buffer contents.
/// The compiler does the heavy lifting.
/// see <https://stackoverflow.com/a/51732799/1345238/>
#[inline]
pub fn buffer_set<T: Clone>(data: &mut [T], from: usize, len: usize, val: T) {
    debug_assert!(from + len <= data.len());
    for p in &mut data[from..(from + len)] {
        *p = val.clone();
    }
}

/// The max value that will be added or subtracted during add mutations
pub const ARITH_MAX: u64 = 35;

/// Interesting 8-bit values from AFL
pub const INTERESTING_8: [i8; 9] = [-128, -1, 0, 1, 16, 32, 64, 100, 127];
/// Interesting 16-bit values from AFL
pub const INTERESTING_16: [i16; 19] = [
    -128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767,
];
/// Interesting 32-bit values from AFL
pub const INTERESTING_32: [i32; 27] = [
    -128,
    -1,
    0,
    1,
    16,
    32,
    64,
    100,
    127,
    -32768,
    -129,
    128,
    255,
    256,
    512,
    1000,
    1024,
    4096,
    32767,
    -2147483648,
    -100663046,
    -32769,
    32768,
    65535,
    65536,
    100663045,
    2147483647,
];

/// Bitflip mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct BitFlipMutator;

impl<I, S> Mutator<I, S> for BitFlipMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let bit = 1 << state.rand_mut().choose(0..8);
            let byte = state.rand_mut().choose(input.bytes_mut());
            *byte ^= bit;
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for BitFlipMutator {
    fn name(&self) -> &str {
        "BitFlipMutator"
    }
}

impl BitFlipMutator {
    /// Creates a new [`BitFlipMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byteflip mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct ByteFlipMutator;

impl<I, S> Mutator<I, S> for ByteFlipMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            *state.rand_mut().choose(input.bytes_mut()) ^= 0xff;
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for ByteFlipMutator {
    fn name(&self) -> &str {
        "ByteFlipMutator"
    }
}

impl ByteFlipMutator {
    /// Creates a new [`ByteFlipMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byte increment mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct ByteIncMutator;

impl<I, S> Mutator<I, S> for ByteIncMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.bytes_mut());
            *byte = byte.wrapping_add(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for ByteIncMutator {
    fn name(&self) -> &str {
        "ByteIncMutator"
    }
}

impl ByteIncMutator {
    /// Creates a new [`ByteIncMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byte decrement mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct ByteDecMutator;

impl<I, S> Mutator<I, S> for ByteDecMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.bytes_mut());
            *byte = byte.wrapping_sub(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for ByteDecMutator {
    fn name(&self) -> &str {
        "ByteDecMutator"
    }
}

impl ByteDecMutator {
    /// Creates a a new [`ByteDecMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byte negate mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct ByteNegMutator;

impl<I, S> Mutator<I, S> for ByteNegMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.bytes_mut());
            *byte = (!(*byte)).wrapping_add(1);
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for ByteNegMutator {
    fn name(&self) -> &str {
        "ByteNegMutator"
    }
}

impl ByteNegMutator {
    /// Creates a new [`ByteNegMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Byte random mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct ByteRandMutator;

impl<I, S> Mutator<I, S> for ByteRandMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let byte = state.rand_mut().choose(input.bytes_mut());
            *byte ^= 1 + state.rand_mut().below(254) as u8;
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for ByteRandMutator {
    fn name(&self) -> &str {
        "ByteRandMutator"
    }
}

impl ByteRandMutator {
    /// Creates a new [`ByteRandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// Helper macro that defines the arithmetic addition/subtraction mutations where random slices
// within the input are treated as u8, u16, u32, or u64, then mutated in place.
macro_rules! add_mutator_impl {
    ($name: ident, $size: ty) => {
        /// Adds or subtracts a random value up to `ARITH_MAX` to a [`<$size>`] at a random place in the [`Vec`], in random byte order.
        #[derive(Default, Debug)]
        pub struct $name;

        #[allow(trivial_numeric_casts)]
        impl<I, S> Mutator<I, S> for $name
        where
            S: HasRand,
            I: HasBytesVec,
        {
            fn mutate(
                &mut self,
                state: &mut S,
                input: &mut I,
                _stage_idx: i32,
            ) -> Result<MutationResult, Error> {
                if input.bytes().len() < size_of::<$size>() {
                    Ok(MutationResult::Skipped)
                } else {
                    // choose a random window of bytes (windows overlap) and convert to $size
                    let (index, bytes) = state
                        .rand_mut()
                        .choose(input.bytes().windows(size_of::<$size>()).enumerate());
                    let val = <$size>::from_ne_bytes(bytes.try_into().unwrap());

                    // mutate
                    let num = 1 + state.rand_mut().below(ARITH_MAX) as $size;
                    let new_val = match state.rand_mut().below(4) {
                        0 => val.wrapping_add(num),
                        1 => val.wrapping_sub(num),
                        2 => val.swap_bytes().wrapping_add(num).swap_bytes(),
                        _ => val.swap_bytes().wrapping_sub(num).swap_bytes(),
                    };

                    // set bytes to mutated value
                    let new_bytes = &mut input.bytes_mut()[index..index + size_of::<$size>()];
                    new_bytes.copy_from_slice(&new_val.to_ne_bytes());
                    Ok(MutationResult::Mutated)
                }
            }
        }

        impl Named for $name {
            fn name(&self) -> &str {
                stringify!($name)
            }
        }

        impl $name {
            /// Creates a new [`$name`].
            #[must_use]
            pub fn new() -> Self {
                Self
            }
        }
    };
}

add_mutator_impl!(ByteAddMutator, u8);
add_mutator_impl!(WordAddMutator, u16);
add_mutator_impl!(DwordAddMutator, u32);
add_mutator_impl!(QwordAddMutator, u64);

///////////////////////////

macro_rules! interesting_mutator_impl {
    ($name: ident, $size: ty, $interesting: ident) => {
        /// Inserts an interesting value at a random place in the input vector
        #[derive(Default, Debug)]
        pub struct $name;

        impl<I, S> Mutator<I, S> for $name
        where
            S: HasRand,
            I: HasBytesVec,
        {
            #[allow(clippy::cast_sign_loss)]
            fn mutate(
                &mut self,
                state: &mut S,
                input: &mut I,
                _stage_idx: i32,
            ) -> Result<MutationResult, Error> {
                if input.bytes().len() < size_of::<$size>() {
                    Ok(MutationResult::Skipped)
                } else {
                    let bytes = input.bytes_mut();
                    let upper_bound = (bytes.len() + 1 - size_of::<$size>()) as u64;
                    let idx = state.rand_mut().below(upper_bound) as usize;
                    let val = *state.rand_mut().choose(&$interesting) as $size;
                    let new_bytes = match state.rand_mut().choose(&[0, 1]) {
                        0 => val.to_be_bytes(),
                        _ => val.to_le_bytes(),
                    };
                    bytes[idx..idx + size_of::<$size>()].copy_from_slice(&new_bytes);
                    Ok(MutationResult::Mutated)
                }
            }
        }

        impl Named for $name {
            fn name(&self) -> &str {
                stringify!($name)
            }
        }

        impl $name {
            /// Creates a new [`$name`].
            #[must_use]
            pub fn new() -> Self {
                Self
            }
        }
    };
}

interesting_mutator_impl!(ByteInterestingMutator, u8, INTERESTING_8);
interesting_mutator_impl!(WordInterestingMutator, u16, INTERESTING_16);
interesting_mutator_impl!(DwordInterestingMutator, u32, INTERESTING_32);

/// Bytes delete mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct BytesDeleteMutator;

impl<I, S> Mutator<I, S> for BytesDeleteMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size <= 2 {
            return Ok(MutationResult::Skipped);
        }

        let off = state.rand_mut().below(size as u64) as usize;
        let len = state.rand_mut().below((size - off) as u64) as usize;
        input.bytes_mut().drain(off..off + len);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesDeleteMutator {
    fn name(&self) -> &str {
        "BytesDeleteMutator"
    }
}

impl BytesDeleteMutator {
    /// Creates a new [`BytesDeleteMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes expand mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct BytesExpandMutator;

impl<I, S> Mutator<I, S> for BytesExpandMutator
where
    S: HasRand + HasMaxSize,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.bytes().len();
        let off = state.rand_mut().below((size + 1) as u64) as usize;
        let mut len = 1 + state.rand_mut().below(16) as usize;

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        input.bytes_mut().resize(size + len, 0);
        buffer_self_copy(input.bytes_mut(), off, off + len, size - off);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesExpandMutator {
    fn name(&self) -> &str {
        "BytesExpandMutator"
    }
}

impl BytesExpandMutator {
    /// Creates a new [`BytesExpandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes insert mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct BytesInsertMutator;

impl<I, S> Mutator<I, S> for BytesInsertMutator
where
    S: HasRand + HasMaxSize,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.bytes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }
        let off = state.rand_mut().below((size + 1) as u64) as usize;
        let mut len = 1 + state.rand_mut().below(16) as usize;

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        let val = input.bytes()[state.rand_mut().below(size as u64) as usize];

        input.bytes_mut().resize(size + len, 0);
        buffer_self_copy(input.bytes_mut(), off, off + len, size - off);
        buffer_set(input.bytes_mut(), off, len, val);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesInsertMutator {
    fn name(&self) -> &str {
        "BytesInsertMutator"
    }
}

impl BytesInsertMutator {
    /// Creates a new [`BytesInsertMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes random insert mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct BytesRandInsertMutator;

impl<I, S> Mutator<I, S> for BytesRandInsertMutator
where
    S: HasRand + HasMaxSize,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.bytes().len();
        let off = state.rand_mut().below((size + 1) as u64) as usize;
        let mut len = 1 + state.rand_mut().below(16) as usize;

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        let val = state.rand_mut().next() as u8;

        input.bytes_mut().resize(size + len, 0);
        buffer_self_copy(input.bytes_mut(), off, off + len, size - off);
        buffer_set(input.bytes_mut(), off, len, val);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesRandInsertMutator {
    fn name(&self) -> &str {
        "BytesRandInsertMutator"
    }
}

impl BytesRandInsertMutator {
    /// Create a new [`BytesRandInsertMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes set mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct BytesSetMutator;

impl<I, S> Mutator<I, S> for BytesSetMutator
where
    S: HasRand,
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
        let off = state.rand_mut().below(size as u64) as usize;
        let len = 1 + state.rand_mut().below(min(16, size - off) as u64) as usize;

        let val = *state.rand_mut().choose(input.bytes());

        buffer_set(input.bytes_mut(), off, len, val);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesSetMutator {
    fn name(&self) -> &str {
        "BytesSetMutator"
    }
}

impl BytesSetMutator {
    /// Creates a new [`BytesSetMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes random set mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct BytesRandSetMutator;

impl<I, S> Mutator<I, S> for BytesRandSetMutator
where
    S: HasRand,
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
        let off = state.rand_mut().below(size as u64) as usize;
        let len = 1 + state.rand_mut().below(min(16, size - off) as u64) as usize;

        let val = state.rand_mut().next() as u8;

        buffer_set(input.bytes_mut(), off, len, val);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesRandSetMutator {
    fn name(&self) -> &str {
        "BytesRandSetMutator"
    }
}

impl BytesRandSetMutator {
    /// Creates a new [`BytesRandSetMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes copy mutation for inputs with a bytes vector
#[derive(Default, Debug)]
pub struct BytesCopyMutator;

impl<I, S> Mutator<I, S> for BytesCopyMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(input.bytes().len() as u64) as usize;
        let to = state.rand_mut().below(input.bytes().len() as u64) as usize;
        let len = 1 + state.rand_mut().below((size - max(from, to)) as u64) as usize;

        buffer_self_copy(input.bytes_mut(), from, to, len);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesCopyMutator {
    fn name(&self) -> &str {
        "BytesCopyMutator"
    }
}

impl BytesCopyMutator {
    /// Creates a new [`BytesCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Bytes insert and self copy mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct BytesInsertCopyMutator {
    tmp_buf: Vec<u8>,
}

impl<I, S> Mutator<I, S> for BytesInsertCopyMutator
where
    S: HasRand + HasMaxSize,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let max_size = state.max_size();
        let size = input.bytes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }
        let off = state.rand_mut().below((size + 1) as u64) as usize;
        let mut len = 1 + state.rand_mut().below(min(16, size as u64)) as usize;

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        let from = if size == len {
            0
        } else {
            state.rand_mut().below((size - len) as u64) as usize
        };

        input.bytes_mut().resize(size + len, 0);
        self.tmp_buf.resize(len, 0);
        buffer_copy(&mut self.tmp_buf, input.bytes(), from, 0, len);

        buffer_self_copy(input.bytes_mut(), off, off + len, size - off);
        buffer_copy(input.bytes_mut(), &self.tmp_buf, 0, off, len);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesInsertCopyMutator {
    fn name(&self) -> &str {
        "BytesInsertCopyMutator"
    }
}

impl BytesInsertCopyMutator {
    /// Creates a new [`BytesInsertCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Bytes swap mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct BytesSwapMutator;

impl<I, S> Mutator<I, S> for BytesSwapMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size <= 1 {
            return Ok(MutationResult::Skipped);
        }

        let first = state.rand_mut().below(input.bytes().len() as u64) as usize;
        let second = state.rand_mut().below(input.bytes().len() as u64) as usize;
        let len = 1 + state.rand_mut().below((size - max(first, second)) as u64) as usize;

        let tmp = input.bytes()[first..(first + len)].to_vec();
        buffer_self_copy(input.bytes_mut(), second, first, len);
        buffer_copy(input.bytes_mut(), &tmp, 0, second, len);

        Ok(MutationResult::Mutated)
    }
}

impl Named for BytesSwapMutator {
    fn name(&self) -> &str {
        "BytesSwapMutator"
    }
}

impl BytesSwapMutator {
    /// Creates a new [`BytesSwapMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Crossover insert mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct CrossoverInsertMutator;

impl<S> Mutator<S::Input, S> for CrossoverInsertMutator
where
    S: HasCorpus + HasRand + HasMaxSize,
    S::Input: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();

        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());

        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_size = state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .load_input()?
            .bytes()
            .len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let max_size = state.max_size();
        let from = state.rand_mut().below(other_size as u64) as usize;
        let to = state.rand_mut().below(size as u64) as usize;
        let mut len = 1 + state.rand_mut().below((other_size - from) as u64) as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input()?;

        if size + len > max_size {
            if max_size > size {
                len = max_size - size;
            } else {
                return Ok(MutationResult::Skipped);
            }
        }

        input.bytes_mut().resize(size + len, 0);
        buffer_self_copy(input.bytes_mut(), to, to + len, size - to);
        buffer_copy(input.bytes_mut(), other.bytes(), from, to, len);

        Ok(MutationResult::Mutated)
    }
}

impl Named for CrossoverInsertMutator {
    fn name(&self) -> &str {
        "CrossoverInsertMutator"
    }
}

impl CrossoverInsertMutator {
    /// Creates a new [`CrossoverInsertMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Crossover replace mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct CrossoverReplaceMutator;

impl<S> Mutator<S::Input, S> for CrossoverReplaceMutator
where
    S: HasCorpus + HasRand,
    S::Input: HasBytesVec,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();
        if size == 0 {
            return Ok(MutationResult::Skipped);
        }

        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let other_size = state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .load_input()?
            .bytes()
            .len();
        if other_size < 2 {
            return Ok(MutationResult::Skipped);
        }

        let from = state.rand_mut().below(other_size as u64) as usize;
        let len = state.rand_mut().below(min(other_size - from, size) as u64) as usize;
        let to = state.rand_mut().below((size - len) as u64) as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input()?;

        buffer_copy(input.bytes_mut(), other.bytes(), from, to, len);

        Ok(MutationResult::Mutated)
    }
}

impl Named for CrossoverReplaceMutator {
    fn name(&self) -> &str {
        "CrossoverReplaceMutator"
    }
}

impl CrossoverReplaceMutator {
    /// Creates a new [`CrossoverReplaceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Returns the first and last diff position between the given vectors, stopping at the min len
fn locate_diffs(this: &[u8], other: &[u8]) -> (i64, i64) {
    let mut first_diff: i64 = -1;
    let mut last_diff: i64 = -1;
    for (i, (this_el, other_el)) in this.iter().zip(other.iter()).enumerate() {
        if this_el != other_el {
            if first_diff < 0 {
                first_diff = i as i64;
            }
            last_diff = i as i64;
        }
    }

    (first_diff, last_diff)
}

/// Splice mutation for inputs with a bytes vector
#[derive(Debug, Default)]
pub struct SpliceMutator;

impl<S> Mutator<S::Input, S> for SpliceMutator
where
    S: HasCorpus + HasRand,
    S::Input: HasBytesVec,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // We don't want to use the testcase we're already using for splicing
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        if let Some(cur) = state.corpus().current() {
            if idx == *cur {
                return Ok(MutationResult::Skipped);
            }
        }

        let (first_diff, last_diff) = {
            let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
            let other = other_testcase.load_input()?;

            let mut counter: u32 = 0;
            loop {
                let (f, l) = locate_diffs(input.bytes(), other.bytes());

                if f != l && f >= 0 && l >= 2 {
                    break (f as u64, l as u64);
                }
                if counter == 3 {
                    return Ok(MutationResult::Skipped);
                }
                counter += 1;
            }
        };

        let split_at = state.rand_mut().between(first_diff, last_diff) as usize;

        let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
        let other = other_testcase.load_input()?;
        input
            .bytes_mut()
            .splice(split_at.., other.bytes()[split_at..].iter().copied());

        Ok(MutationResult::Mutated)
    }
}

impl Named for SpliceMutator {
    fn name(&self) -> &str {
        "SpliceMutator"
    }
}

impl SpliceMutator {
    /// Creates a new [`SpliceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

// Converts a hex u8 to its u8 value: 'A' -> 10 etc.
fn from_hex(hex: u8) -> Result<u8, Error> {
    match hex {
        48..=57 => Ok(hex - 48),
        65..=70 => Ok(hex - 55),
        97..=102 => Ok(hex - 87),
        _ => Err(Error::illegal_argument("Invalid hex character".to_owned())),
    }
}

/// Decodes a dictionary token: 'foo\x41\\and\"bar' -> 'fooA\and"bar'
pub fn str_decode(item: &str) -> Result<Vec<u8>, Error> {
    let mut token: Vec<u8> = Vec::new();
    let item: Vec<u8> = item.as_bytes().to_vec();
    let backslash: u8 = 92; // '\\'
    let mut take_next: bool = false;
    let mut take_next_two: u32 = 0;
    let mut decoded: u8 = 0;

    for c in item {
        if take_next_two == 1 {
            decoded = from_hex(c)? << 4;
            take_next_two = 2;
        } else if take_next_two == 2 {
            decoded += from_hex(c)?;
            token.push(decoded);
            take_next_two = 0;
        } else if c != backslash || take_next {
            if take_next && (c == 120 || c == 88) {
                take_next_two = 1;
            } else {
                token.push(c);
            }
            take_next = false;
        } else {
            take_next = true;
        }
    }

    Ok(token)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        bolts::{
            rands::StdRand,
            tuples::{tuple_list, HasConstLen},
        },
        corpus::{Corpus, InMemoryCorpus},
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        mutators::MutatorsTuple,
        state::{HasMetadata, StdState},
    };

    fn test_mutations<I, S>() -> impl MutatorsTuple<I, S>
    where
        S: HasRand + HasMetadata + HasMaxSize,
        I: HasBytesVec,
    {
        tuple_list!(
            BitFlipMutator::new(),
            ByteFlipMutator::new(),
            ByteIncMutator::new(),
            ByteDecMutator::new(),
            ByteNegMutator::new(),
            ByteRandMutator::new(),
            ByteAddMutator::new(),
            WordAddMutator::new(),
            DwordAddMutator::new(),
            QwordAddMutator::new(),
            ByteInterestingMutator::new(),
            WordInterestingMutator::new(),
            DwordInterestingMutator::new(),
            BytesDeleteMutator::new(),
            BytesDeleteMutator::new(),
            BytesDeleteMutator::new(),
            BytesDeleteMutator::new(),
            BytesExpandMutator::new(),
            BytesInsertMutator::new(),
            BytesRandInsertMutator::new(),
            BytesSetMutator::new(),
            BytesRandSetMutator::new(),
            BytesCopyMutator::new(),
            BytesSwapMutator::new(),
        )
    }

    #[test]
    fn test_mutators() {
        let mut inputs = vec![
            BytesInput::new(vec![0x13, 0x37]),
            BytesInput::new(vec![0xFF; 2048]),
            BytesInput::new(vec![]),
            BytesInput::new(vec![0xFF; 50000]),
            BytesInput::new(vec![0x0]),
            BytesInput::new(vec![]),
            BytesInput::new(vec![1; 4]),
        ];

        let rand = StdRand::with_seed(1337);
        let mut corpus = InMemoryCorpus::new();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        corpus
            .add(BytesInput::new(vec![0x42; 0x1337]).into())
            .unwrap();

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut mutations = test_mutations();
        for _ in 0..2 {
            let mut new_testcases = vec![];
            for idx in 0..(mutations.len()) {
                for input in &inputs {
                    let mut mutant = input.clone();
                    match mutations
                        .get_and_mutate(idx.into(), &mut state, &mut mutant, 0)
                        .unwrap()
                    {
                        MutationResult::Mutated => new_testcases.push(mutant),
                        MutationResult::Skipped => (),
                    };
                }
            }
            inputs.append(&mut new_testcases);
        }
    }
}
