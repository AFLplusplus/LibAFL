//! A wide variety of mutations used during fuzzing.

use crate::{
    bolts::tuples::Named,
    corpus::Corpus,
    inputs::{HasBytesVec, Input},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasMaxSize, HasRand},
    utils::Rand,
    Error,
};

use alloc::{borrow::ToOwned, vec::Vec};
use core::{
    cmp::{max, min},
    marker::PhantomData,
};

/// Mem move in the own vec
#[inline]
pub fn buffer_self_copy(data: &mut [u8], from: usize, to: usize, len: usize) {
    debug_assert!(!data.is_empty());
    debug_assert!(from + len <= data.len());
    debug_assert!(to + len <= data.len());
    if len != 0 && from != to {
        let ptr = data.as_mut_ptr();
        unsafe { core::ptr::copy(ptr.add(from), ptr.add(to), len) }
    }
}

/// Mem move between vecs
#[inline]
pub fn buffer_copy(dst: &mut [u8], src: &[u8], from: usize, to: usize, len: usize) {
    debug_assert!(!dst.is_empty());
    debug_assert!(!src.is_empty());
    debug_assert!(from + len <= src.len());
    debug_assert!(to + len <= dst.len());
    let dst_ptr = dst.as_mut_ptr();
    let src_ptr = src.as_ptr();
    if len != 0 {
        unsafe { core::ptr::copy(src_ptr.add(from), dst_ptr.add(to), len) }
    }
}

/// A simple way to set buffer contents.
/// The compiler does the heavy lifting.
/// see <https://stackoverflow.com/a/51732799/1345238/>
#[inline]
fn buffer_set(data: &mut [u8], from: usize, len: usize, val: u8) {
    debug_assert!(from + len <= data.len());
    for p in &mut data[from..(from + len)] {
        *p = val
    }
}

const ARITH_MAX: u64 = 35;

const INTERESTING_8: [i8; 9] = [-128, -1, 0, 1, 16, 32, 64, 100, 127];
const INTERESTING_16: [i16; 19] = [
    -128, -1, 0, 1, 16, 32, 64, 100, 127, -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767,
];
const INTERESTING_32: [i32; 27] = [
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
#[derive(Default)]
pub struct BitFlipMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BitFlipMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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
            let bit = state.rand_mut().below((input.bytes().len() << 3) as u64) as usize;
            unsafe {
                // Moar speed, no bound check
                *input.bytes_mut().get_unchecked_mut(bit >> 3) ^= (128u8 >> (bit & 7)) as u8;
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for BitFlipMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "BitFlipMutator"
    }
}

impl<I, R, S> BitFlipMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`BitFlipMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Byteflip mutation for inputs with a bytes vector
#[derive(Default)]
pub struct ByteFlipMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for ByteFlipMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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
            let idx = state.rand_mut().below(input.bytes().len() as u64) as usize;
            unsafe {
                // Moar speed, no bound check
                *input.bytes_mut().get_unchecked_mut(idx) ^= 0xff;
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for ByteFlipMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ByteFlipMutator"
    }
}

impl<I, R, S> ByteFlipMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`ByteFlipMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Byte increment mutation for inputs with a bytes vector
#[derive(Default)]
pub struct ByteIncMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for ByteIncMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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
            let idx = state.rand_mut().below(input.bytes().len() as u64) as usize;
            unsafe {
                // Moar speed, no bound check
                let ptr = input.bytes_mut().get_unchecked_mut(idx);
                *ptr = (*ptr).wrapping_add(1);
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for ByteIncMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ByteIncMutator"
    }
}

impl<I, R, S> ByteIncMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`ByteIncMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Byte decrement mutation for inputs with a bytes vector
#[derive(Default)]
pub struct ByteDecMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for ByteDecMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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
            let idx = state.rand_mut().below(input.bytes().len() as u64) as usize;
            unsafe {
                // Moar speed, no bound check
                let ptr = input.bytes_mut().get_unchecked_mut(idx);
                *ptr = (*ptr).wrapping_sub(1);
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for ByteDecMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ByteDecMutator"
    }
}

impl<I, R, S> ByteDecMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a a new [`ByteDecMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Byte negate mutation for inputs with a bytes vector
#[derive(Default)]
pub struct ByteNegMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for ByteNegMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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
            let idx = state.rand_mut().below(input.bytes().len() as u64) as usize;
            unsafe {
                // Moar speed, no bound check
                *input.bytes_mut().get_unchecked_mut(idx) = !(*input.bytes().get_unchecked(idx));
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for ByteNegMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ByteNegMutator"
    }
}

impl<I, R, S> ByteNegMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`ByteNegMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Byte random mutation for inputs with a bytes vector
#[derive(Default)]
pub struct ByteRandMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for ByteRandMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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
            let idx = state.rand_mut().below(input.bytes().len() as u64) as usize;
            unsafe {
                // Moar speed, no bound check
                *input.bytes_mut().get_unchecked_mut(idx) = state.rand_mut().below(256) as u8;
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for ByteRandMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ByteRandMutator"
    }
}

impl<I, R, S> ByteRandMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`ByteRandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Byte add mutation for inputs with a bytes vector
#[derive(Default)]
pub struct ByteAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for ByteAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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
            let idx = state.rand_mut().below(input.bytes().len() as u64) as usize;
            unsafe {
                // Moar speed, no bound check
                let ptr = input.bytes_mut().get_unchecked_mut(idx) as *mut u8;
                let num = 1 + state.rand_mut().below(ARITH_MAX) as u8;
                match state.rand_mut().below(2) {
                    0 => *ptr = (*ptr).wrapping_add(num),
                    _ => *ptr = (*ptr).wrapping_sub(num),
                };
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for ByteAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ByteAddMutator"
    }
}

impl<I, R, S> ByteAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`ByteAddMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Word add mutation for inputs with a bytes vector
#[derive(Default)]
pub struct WordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for WordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().len() < 2 {
            Ok(MutationResult::Skipped)
        } else {
            let idx = state.rand_mut().below(input.bytes().len() as u64 - 1) as usize;
            unsafe {
                // Moar speed, no bounds checks
                let ptr = input.bytes_mut().get_unchecked_mut(idx) as *mut _ as *mut u16;
                let num = 1 + state.rand_mut().below(ARITH_MAX) as u16;
                match state.rand_mut().below(4) {
                    0 => *ptr = (*ptr).wrapping_add(num),
                    1 => *ptr = (*ptr).wrapping_sub(num),
                    2 => *ptr = ((*ptr).swap_bytes().wrapping_add(num)).swap_bytes(),
                    _ => *ptr = ((*ptr).swap_bytes().wrapping_sub(num)).swap_bytes(),
                };
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for WordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "WordAddMutator"
    }
}

impl<I, R, S> WordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`WordAddMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Dword add mutation for inputs with a bytes vector
#[derive(Default)]
pub struct DwordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for DwordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().len() < 4 {
            Ok(MutationResult::Skipped)
        } else {
            let idx = state.rand_mut().below(input.bytes().len() as u64 - 3) as usize;
            unsafe {
                // Moar speed, no bound check
                let ptr = input.bytes_mut().get_unchecked_mut(idx) as *mut _ as *mut u32;
                let num = 1 + state.rand_mut().below(ARITH_MAX) as u32;
                match state.rand_mut().below(4) {
                    0 => *ptr = (*ptr).wrapping_add(num),
                    1 => *ptr = (*ptr).wrapping_sub(num),
                    2 => *ptr = ((*ptr).swap_bytes().wrapping_add(num)).swap_bytes(),
                    _ => *ptr = ((*ptr).swap_bytes().wrapping_sub(num)).swap_bytes(),
                };
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for DwordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "DwordAddMutator"
    }
}

impl<I, R, S> DwordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`DwordAddMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Qword add mutation for inputs with a bytes vector
#[derive(Default)]
pub struct QwordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for QwordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().len() < 8 {
            Ok(MutationResult::Skipped)
        } else {
            let idx = state.rand_mut().below(input.bytes().len() as u64 - 7) as usize;
            unsafe {
                // Moar speed, no bounds checks
                let ptr = input.bytes_mut().get_unchecked_mut(idx) as *mut _ as *mut u64;
                let num = 1 + state.rand_mut().below(ARITH_MAX) as u64;
                match state.rand_mut().below(4) {
                    0 => *ptr = (*ptr).wrapping_add(num),
                    1 => *ptr = (*ptr).wrapping_sub(num),
                    2 => *ptr = ((*ptr).swap_bytes().wrapping_add(num)).swap_bytes(),
                    _ => *ptr = ((*ptr).swap_bytes().wrapping_sub(num)).swap_bytes(),
                };
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for QwordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "QwordAddMutator"
    }
}

impl<I, R, S> QwordAddMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`QwordAddMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Byte interesting mutation for inputs with a bytes vector
#[derive(Default)]
pub struct ByteInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for ByteInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let idx = state.rand_mut().below(input.bytes().len() as u64) as usize;
            let val =
                INTERESTING_8[state.rand_mut().below(INTERESTING_8.len() as u64) as usize] as u8;
            unsafe {
                // Moar speed, no bound check
                *input.bytes_mut().get_unchecked_mut(idx) = val;
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for ByteInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "ByteInterestingMutator"
    }
}

impl<I, R, S> ByteInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`ByteInterestingMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Word interesting mutation for inputs with a bytes vector
#[derive(Default)]
pub struct WordInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for WordInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().len() < 2 {
            Ok(MutationResult::Skipped)
        } else {
            let idx = state.rand_mut().below(input.bytes().len() as u64 - 1) as usize;
            let val =
                INTERESTING_16[state.rand_mut().below(INTERESTING_8.len() as u64) as usize] as u16;
            unsafe {
                // Moar speed, no bounds checks
                let ptr = input.bytes_mut().get_unchecked_mut(idx) as *mut _ as *mut u16;
                if state.rand_mut().below(2) == 0 {
                    *ptr = val;
                } else {
                    *ptr = val.swap_bytes();
                }
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for WordInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "WordInterestingMutator"
    }
}

impl<I, R, S> WordInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`WordInterestingMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Dword interesting mutation for inputs with a bytes vector
#[derive(Default)]
pub struct DwordInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for DwordInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if input.bytes().len() < 4 {
            Ok(MutationResult::Skipped)
        } else {
            let idx = state.rand_mut().below(input.bytes().len() as u64 - 3) as usize;
            let val =
                INTERESTING_32[state.rand_mut().below(INTERESTING_8.len() as u64) as usize] as u32;
            unsafe {
                // Moar speed, no bounds checks
                let ptr = input.bytes_mut().get_unchecked_mut(idx) as *mut _ as *mut u32;
                if state.rand_mut().below(2) == 0 {
                    *ptr = val;
                } else {
                    *ptr = val.swap_bytes();
                }
            }
            Ok(MutationResult::Mutated)
        }
    }
}

impl<I, R, S> Named for DwordInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "DwordInterestingMutator"
    }
}

impl<I, R, S> DwordInterestingMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`DwordInterestingMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Bytes delete mutation for inputs with a bytes vector
#[derive(Default)]
pub struct BytesDeleteMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BytesDeleteMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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

impl<I, R, S> Named for BytesDeleteMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "BytesDeleteMutator"
    }
}

impl<I, R, S> BytesDeleteMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`BytesDeleteMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Bytes expand mutation for inputs with a bytes vector
#[derive(Default)]
pub struct BytesExpandMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BytesExpandMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
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

impl<I, R, S> Named for BytesExpandMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn name(&self) -> &str {
        "BytesExpandMutator"
    }
}

impl<I, R, S> BytesExpandMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    /// Creates a new [`BytesExpandMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Bytes insert mutation for inputs with a bytes vector
#[derive(Default)]
pub struct BytesInsertMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BytesInsertMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
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

impl<I, R, S> Named for BytesInsertMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn name(&self) -> &str {
        "BytesInsertMutator"
    }
}

impl<I, R, S> BytesInsertMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    /// Creates a new [`BytesInsertMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Bytes random insert mutation for inputs with a bytes vector
#[derive(Default)]
pub struct BytesRandInsertMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BytesRandInsertMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
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

        let val = state.rand_mut().below(256) as u8;

        input.bytes_mut().resize(size + len, 0);
        buffer_self_copy(input.bytes_mut(), off, off + len, size - off);
        buffer_set(input.bytes_mut(), off, len, val);

        Ok(MutationResult::Mutated)
    }
}

impl<I, R, S> Named for BytesRandInsertMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    fn name(&self) -> &str {
        "BytesRandInsertMutator"
    }
}

impl<I, R, S> BytesRandInsertMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    /// Create a new [`BytesRandInsertMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Bytes set mutation for inputs with a bytes vector
#[derive(Default)]
pub struct BytesSetMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BytesSetMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
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
        let off = state.rand_mut().below(size as u64) as usize;
        let len = 1 + state.rand_mut().below(min(16, size - off) as u64) as usize;

        let val = input.bytes()[state.rand_mut().below(size as u64) as usize];

        buffer_set(input.bytes_mut(), off, len, val);

        Ok(MutationResult::Mutated)
    }
}

impl<I, R, S> Named for BytesSetMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "BytesSetMutator"
    }
}

impl<I, R, S> BytesSetMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`BytesSetMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Bytes random set mutation for inputs with a bytes vector
#[derive(Default)]
pub struct BytesRandSetMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BytesRandSetMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
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
        let off = state.rand_mut().below(size as u64) as usize;
        let len = 1 + state.rand_mut().below(min(16, size - off) as u64) as usize;

        let val = state.rand_mut().below(256) as u8;

        buffer_set(input.bytes_mut(), off, len, val);

        Ok(MutationResult::Mutated)
    }
}

impl<I, R, S> Named for BytesRandSetMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "BytesRandSetMutator"
    }
}

impl<I, R, S> BytesRandSetMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`BytesRandSetMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Bytes copy mutation for inputs with a bytes vector
#[derive(Default)]
pub struct BytesCopyMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BytesCopyMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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

impl<I, R, S> Named for BytesCopyMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "BytesCopyMutator"
    }
}

impl<I, R, S> BytesCopyMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`BytesCopyMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Bytes swap mutation for inputs with a bytes vector
#[derive(Default)]
pub struct BytesSwapMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    phantom: PhantomData<(I, R, S)>,
}

impl<I, R, S> Mutator<I, S> for BytesSwapMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
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

impl<I, R, S> Named for BytesSwapMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    fn name(&self) -> &str {
        "BytesSwapMutator"
    }
}

impl<I, R, S> BytesSwapMutator<I, R, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    /// Creates a new [`BytesSwapMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Crossover insert mutation for inputs with a bytes vector
#[derive(Default)]
pub struct CrossoverInsertMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I> + HasMaxSize,
{
    phantom: PhantomData<(C, I, R, S)>,
}

impl<C, I, R, S> Mutator<I, S> for CrossoverInsertMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I> + HasMaxSize,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();

        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
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
        let mut len = state.rand_mut().below((other_size - from) as u64) as usize;

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

impl<C, I, R, S> Named for CrossoverInsertMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I> + HasMaxSize,
{
    fn name(&self) -> &str {
        "CrossoverInsertMutator"
    }
}

impl<C, I, R, S> CrossoverInsertMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I> + HasMaxSize,
{
    /// Creates a new [`CrossoverInsertMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

/// Crossover replace mutation for inputs with a bytes vector
#[derive(Default)]
pub struct CrossoverReplaceMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
    phantom: PhantomData<(C, I, R, S)>,
}

impl<C, I, R, S> Mutator<I, S> for CrossoverReplaceMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let size = input.bytes().len();

        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
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

impl<C, I, R, S> Named for CrossoverReplaceMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
    fn name(&self) -> &str {
        "CrossoverReplaceMutator"
    }
}

impl<C, I, R, S> CrossoverReplaceMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
    /// Creates a new [`CrossoverReplaceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
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
#[derive(Default)]
pub struct SpliceMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
    phantom: PhantomData<(C, I, R, S)>,
}

impl<C, I, R, S> Mutator<I, S> for SpliceMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
    #[allow(clippy::cast_sign_loss)]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        // We don't want to use the testcase we're already using for splicing
        let count = state.corpus().count();
        let idx = state.rand_mut().below(count as u64) as usize;
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
            .splice(split_at.., other.bytes()[split_at..].iter().cloned());

        Ok(MutationResult::Mutated)
    }
}

impl<C, I, R, S> Named for SpliceMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
    fn name(&self) -> &str {
        "SpliceMutator"
    }
}

impl<C, I, R, S> SpliceMutator<C, I, R, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
    /// Creates a new [`SpliceMutator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

// Converts a hex u8 to its u8 value: 'A' -> 10 etc.
fn from_hex(hex: u8) -> Result<u8, Error> {
    if (48..=57).contains(&hex) {
        return Ok(hex - 48);
    }
    if (65..=70).contains(&hex) {
        return Ok(hex - 55);
    }
    if (97..=102).contains(&hex) {
        return Ok(hex - 87);
    }
    Err(Error::IllegalArgument("".to_owned()))
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
        bolts::tuples::tuple_list,
        bolts::tuples::HasLen,
        corpus::{Corpus, InMemoryCorpus},
        inputs::BytesInput,
        mutators::MutatorsTuple,
        state::{HasMetadata, State},
        utils::StdRand,
    };

    fn test_mutations<C, I, R, S>() -> impl MutatorsTuple<I, S>
    where
        I: Input + HasBytesVec,
        S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
        C: Corpus<I>,
        R: Rand,
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

        corpus
            .add(BytesInput::new(vec![0x42; 0x1337]).into())
            .unwrap();

        let mut state = State::new(rand, corpus, (), InMemoryCorpus::new(), ());

        let mut mutations = test_mutations();
        for _ in 0..2 {
            let mut new_testcases = vec![];
            for idx in 0..(mutations.len()) {
                for input in &inputs {
                    let mut mutant = input.clone();
                    match mutations
                        .get_and_mutate(idx, &mut state, &mut mutant, 0)
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
