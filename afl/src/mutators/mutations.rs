use crate::inputs::{HasBytesVec, Input};
use crate::mutators::Corpus;
use crate::mutators::*;
use crate::utils::Rand;
use crate::AflError;

pub enum MutationResult {
    Mutated,
    Skipped,
}

// TODO maybe the mutator arg is not needed
/// The generic function type that identifies mutations
pub type MutationFunction<M, C, I, R> =
    fn(&mut M, &mut R, &C, &mut I) -> Result<MutationResult, AflError>;

pub trait ComposedByMutations<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Get a mutation by index
    fn mutation_by_idx(&self, index: usize) -> MutationFunction<Self, C, I, R>;

    /// Get the number of mutations
    fn mutations_count(&self) -> usize;

    /// Add a mutation
    fn add_mutation(&mut self, mutation: MutationFunction<Self, C, I, R>);
}

/// Bitflip mutation for inputs with a bytes vector
pub fn mutation_bitflip<M, C, I, R>(
    _mutator: &mut M,
    rand: &mut R,
    _corpus: &C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    if input.bytes().len() == 0 {
        Ok(MutationResult::Skipped)
    } else {
        let bit = rand.below((input.bytes().len() << 3) as u64) as usize;
        unsafe {
            // moar speed, no bound check
            *input.bytes_mut().get_unchecked_mut(bit >> 3) ^= (128 >> (bit & 7)) as u8;
        }
        Ok(MutationResult::Mutated)
    }
}

pub fn mutation_byteflip<M, C, I, R>(
    _mutator: &mut M,
    rand: &mut R,
    _corpus: &C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    if input.bytes().len() == 0 {
        Ok(MutationResult::Skipped)
    } else {
        let idx = rand.below(input.bytes().len() as u64) as usize;
        unsafe {
            // moar speed, no bound check
            *input.bytes_mut().get_unchecked_mut(idx) ^= 0xff;
        }
        Ok(MutationResult::Mutated)
    }
}

pub fn mutation_byteinc<M, C, I, R>(
    _mutator: &mut M,
    rand: &mut R,
    _corpus: &C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    if input.bytes().len() == 0 {
        Ok(MutationResult::Skipped)
    } else {
        let idx = rand.below(input.bytes().len() as u64) as usize;
        unsafe {
            // moar speed, no bound check
            *input.bytes_mut().get_unchecked_mut(idx) += 1;
        }
        Ok(MutationResult::Mutated)
    }
}

pub fn mutation_bytedec<M, C, I, R>(
    _mutator: &mut M,
    rand: &mut R,
    _corpus: &C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    if input.bytes().len() == 0 {
        Ok(MutationResult::Skipped)
    } else {
        let idx = rand.below(input.bytes().len() as u64) as usize;
        unsafe {
            // moar speed, no bound check
            *input.bytes_mut().get_unchecked_mut(idx) -= 1;
        }
        Ok(MutationResult::Mutated)
    }
}

pub fn mutation_byteneg<M, C, I, R>(
    _mutator: &mut M,
    rand: &mut R,
    _corpus: &C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    if input.bytes().len() == 0 {
        Ok(MutationResult::Skipped)
    } else {
        let idx = rand.below(input.bytes().len() as u64) as usize;
        unsafe {
            // moar speed, no bound check
            *input.bytes_mut().get_unchecked_mut(idx) = !(*input.bytes().get_unchecked(idx));
        }
        Ok(MutationResult::Mutated)
    }
}

/*
pub fn mutation_bytesexpand<M, C, I, R>(
    mutator: &mut M,
    rand: &mut R,
    _corpus: &C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R> + HasMaxSize,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    let len = rand.below(mutator.max_size() as u64) as usize;


    Ok(MutationResult::Mutated)
}
*/

pub fn mutation_bytesdelete<M, C, I, R>(
    _mutator: &mut M,
    rand: &mut R,
    _corpus: & C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    let size = input.bytes().len();
    if size <= 2 {
        return Ok(MutationResult::Skipped);
    }

    let off = rand.below(size as u64) as usize;
    let len = rand.below((size - off) as u64) as usize;
    input.bytes_mut().drain(off..len);

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

/// Splicing mutator
pub fn mutation_splice<M, C, I, R>(
    _mutator: &mut M,
    rand: &mut R,
    corpus: & C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    // We don't want to use the testcase we're already using for splicing
    let (other_testcase, _) = corpus.random_entry(rand)?.clone();
    // TODO: Load let other = Testcase::load_from_disk(other_test)?;
    // println!("Input: {:?}, other input: {:?}", input.bytes(), other.bytes());
    let other = match other_testcase.input() {
        Some(i) => i,
        None => return Ok(MutationResult::Skipped), //TODO
    };

    let mut counter = 0;
    let (first_diff, last_diff) = loop {
        let (f, l) = locate_diffs(input.bytes(), other.bytes());
        // println!("Diffs were between {} and {}", f, l);
        if f != l && f >= 0 && l >= 2 {
            break (f, l);
        }
        if counter == 3 {
            return Ok(MutationResult::Skipped);
        }
        counter += 1;
    };

    let split_at = rand.between(first_diff as u64, last_diff as u64) as usize;

    // println!("Splicing at {}", split_at);

    input
        .bytes_mut()
        .splice(split_at.., other.bytes()[split_at..].iter().cloned());

    // println!("Splice result: {:?}, input is now: {:?}", split_result, input.bytes());

    Ok(MutationResult::Mutated)
}
