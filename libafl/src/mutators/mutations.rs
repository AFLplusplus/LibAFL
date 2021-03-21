//! A wide variety of mutations used during fuzzing.

use crate::{
    corpus::Corpus,
    inputs::{HasBytesVec, Input},
    state::{HasCorpus, HasMaxSize, HasRand},
    utils::Rand,
    Error,
};

use alloc::{borrow::ToOwned, vec::Vec};
use core::cmp::{max, min};

/// The result of a mutation.
/// If the mutation got skipped, the target
/// will not be executed with the returned input.
#[derive(Clone, Copy, Debug)]
pub enum MutationResult {
    Mutated,
    Skipped,
}

#[derive(Clone, Copy, Debug)]
pub enum MutationType {
    MutationBitflip,
    MutationByteflip,
    MutationByteinc,
    MutationBytedec,
    MutationByteneg,
    MutationByterand,
    MutationByteadd,
    MutationWordadd,
    MutationDwordadd,
    MutationQwordadd,
    MutationByteinteresting,
    MutationWordinteresting,
    MutationDwordinteresting,
    MutationBytesdelete,
    MutationBytesexpand,
    MutationBytesinsert,
    MutationBytesrandinsert,
    MutationBytesset,
    MutationBytesrandset,
    MutationBytescopy,
    MutationBytesswap,
    MutationTokenInsert,
    MutationTokenReplace,
    MutationCrossoverInsert,
    MutationCrossoverReplace,
    MutationSplice,
}

// TODO maybe the mutator arg is not needed
/// The generic function type that identifies mutations
pub type MutationFunction<I, S> = fn(&mut S, &mut I) -> Result<MutationResult, Error>;

pub trait ComposedByMutations<I, S>
where
    I: Input,
{
    /// Get a mutation by index
    fn mutation_by_idx(&self, index: usize) -> (MutationFunction<I, S>, MutationType);

    /// Get the number of mutations
    fn mutations_count(&self) -> usize;

    /// Add a mutation
    fn add_mutation(&mut self, mutation: (MutationFunction<I, S>, MutationType));
}

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

/// A simple buffer_set.
/// The compiler does the heavy lifting.
/// see https://stackoverflow.com/a/51732799/1345238
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
pub fn mutation_bitflip<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
    if input.bytes().is_empty() {
        Ok(MutationResult::Skipped)
    } else {
        let bit = state.rand_mut().below((input.bytes().len() << 3) as u64) as usize;
        unsafe {
            // Moar speed, no bound check
            *input.bytes_mut().get_unchecked_mut(bit >> 3) ^= (128 >> (bit & 7)) as u8;
        }
        Ok(MutationResult::Mutated)
    }
}

pub fn mutation_byteflip<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_byteinc<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_bytedec<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_byteneg<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_byterand<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_byteadd<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_wordadd<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    if input.bytes().len() < 2 {
        Ok(MutationResult::Skipped)
    } else {
        let idx = state.rand_mut().below(input.bytes().len() as u64 - 1) as usize;
        unsafe {
            // Moar speed, no bound check
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

pub fn mutation_dwordadd<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_qwordadd<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    if input.bytes().len() < 8 {
        Ok(MutationResult::Skipped)
    } else {
        let idx = state.rand_mut().below(input.bytes().len() as u64 - 7) as usize;
        unsafe {
            // Moar speed, no bound check
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

pub fn mutation_byteinteresting<I, R, S>(
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    if input.bytes().is_empty() {
        Ok(MutationResult::Skipped)
    } else {
        let idx = state.rand_mut().below(input.bytes().len() as u64) as usize;
        let val = INTERESTING_8[state.rand_mut().below(INTERESTING_8.len() as u64) as usize] as u8;
        unsafe {
            // Moar speed, no bound check
            *input.bytes_mut().get_unchecked_mut(idx) = val;
        }
        Ok(MutationResult::Mutated)
    }
}

pub fn mutation_wordinteresting<I, R, S>(
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    if input.bytes().len() < 2 {
        Ok(MutationResult::Skipped)
    } else {
        let idx = state.rand_mut().below(input.bytes().len() as u64 - 1) as usize;
        let val =
            INTERESTING_16[state.rand_mut().below(INTERESTING_8.len() as u64) as usize] as u16;
        unsafe {
            // Moar speed, no bound check
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

pub fn mutation_dwordinteresting<I, R, S>(
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    if input.bytes().len() < 4 {
        Ok(MutationResult::Skipped)
    } else {
        let idx = state.rand_mut().below(input.bytes().len() as u64 - 3) as usize;
        let val =
            INTERESTING_32[state.rand_mut().below(INTERESTING_8.len() as u64) as usize] as u32;
        unsafe {
            // Moar speed, no bound check
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

pub fn mutation_bytesdelete<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
    let size = input.bytes().len();
    if size <= 2 {
        return Ok(MutationResult::Skipped);
    }

    let off = state.rand_mut().below(size as u64) as usize;
    let len = state.rand_mut().below((size - off) as u64) as usize;
    input.bytes_mut().drain(off..off + len);

    Ok(MutationResult::Mutated)
}

pub fn mutation_bytesexpand<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
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

pub fn mutation_bytesinsert<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
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

pub fn mutation_bytesrandinsert<I, R, S>(
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasMaxSize,
    R: Rand,
{
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

pub fn mutation_bytesset<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_bytesrandset<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_bytescopy<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

pub fn mutation_bytesswap<I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    I: Input + HasBytesVec,
    S: HasRand<R>,
    R: Rand,
{
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

/// Crossover insert mutation
pub fn mutation_crossover_insert<C, I, R, S>(
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I> + HasMaxSize,
{
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

/// Crossover replace mutation
pub fn mutation_crossover_replace<C, I, R, S>(
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, Error>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
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

/// Splicing mutation from AFL
pub fn mutation_splice<C, I, R, S>(state: &mut S, input: &mut I) -> Result<MutationResult, Error>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
{
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

        let mut counter = 0;
        loop {
            let (f, l) = locate_diffs(input.bytes(), other.bytes());

            if f != l && f >= 0 && l >= 2 {
                break (f, l);
            }
            if counter == 3 {
                return Ok(MutationResult::Skipped);
            }
            counter += 1;
        }
    };

    let split_at = state
        .rand_mut()
        .between(first_diff as u64, last_diff as u64) as usize;

    let mut other_testcase = state.corpus().get(idx)?.borrow_mut();
    let other = other_testcase.load_input()?;
    input
        .bytes_mut()
        .splice(split_at.., other.bytes()[split_at..].iter().cloned());

    Ok(MutationResult::Mutated)
}

// Converts a hex u8 to its u8 value: 'A' -> 10 etc.
fn from_hex(hex: u8) -> Result<u8, Error> {
    if hex >= 48 && hex <= 57 {
        return Ok(hex - 48);
    }
    if hex >= 65 && hex <= 70 {
        return Ok(hex - 55);
    }
    if hex >= 97 && hex <= 102 {
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
        } else {
            if c != backslash || take_next {
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
    }

    Ok(token)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        corpus::{Corpus, InMemoryCorpus},
        inputs::BytesInput,
        mutators::{mutation_tokeninsert, mutation_tokenreplace},
        state::State,
        utils::StdRand,
    };

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

        let mut mutations: Vec<MutationFunction<_, _>> = vec![];

        mutations.push(mutation_bitflip);
        mutations.push(mutation_byteflip);
        mutations.push(mutation_byteinc);
        mutations.push(mutation_bytedec);
        mutations.push(mutation_byteneg);
        mutations.push(mutation_byterand);
        mutations.push(mutation_byteadd);
        mutations.push(mutation_wordadd);
        mutations.push(mutation_dwordadd);
        mutations.push(mutation_qwordadd);
        mutations.push(mutation_byteinteresting);
        mutations.push(mutation_wordinteresting);
        mutations.push(mutation_dwordinteresting);

        mutations.push(mutation_bytesdelete);
        mutations.push(mutation_bytesdelete);
        mutations.push(mutation_bytesdelete);
        mutations.push(mutation_bytesdelete);
        mutations.push(mutation_bytesexpand);
        mutations.push(mutation_bytesinsert);
        mutations.push(mutation_bytesrandinsert);
        mutations.push(mutation_bytesset);
        mutations.push(mutation_bytesrandset);
        mutations.push(mutation_bytescopy);
        mutations.push(mutation_bytesswap);

        mutations.push(mutation_tokeninsert);
        mutations.push(mutation_tokenreplace);

        for _ in 0..2 {
            let mut new_testcases = vec![];
            for mutation in &mutations {
                for input in inputs.iter() {
                    let mut mutant = input.clone();
                    match mutation(&mut state, &mut mutant).unwrap() {
                        MutationResult::Mutated => new_testcases.push(mutant),
                        MutationResult::Skipped => (),
                    };
                }
            }
            inputs.append(&mut new_testcases);
        }
    }
}
