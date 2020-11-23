use crate::inputs::{HasBytesVec, Input};
use crate::mutators::Corpus;
use crate::mutators::Mutator;
use crate::utils::Rand;
use crate::AflError;

use alloc::vec::Vec;
use core::marker::PhantomData;

pub enum MutationResult {
    Mutated,
    Skipped,
}

// TODO maybe the mutator arg is not needed
/// The generic function type that identifies mutations
type MutationFunction<M, C, I, R> =
    fn(&mut M, &mut R, &mut C, &mut I) -> Result<MutationResult, AflError>;

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

pub trait ScheduledMutator<C, I, R>: Mutator<C, I, R> + ComposedByMutations<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&mut self, rand: &mut R, _input: &I) -> u64 {
        1 << (1 + rand.below(6))
    }

    /// Get the next mutation to apply
    fn schedule(
        &mut self,
        rand: &mut R,
        _input: &I,
    ) -> Result<MutationFunction<Self, C, I, R>, AflError> {
        let count = self.mutations_count() as u64;
        if count == 0 {
            return Err(AflError::Empty("no mutations".into()));
        }
        let idx;
        {
            idx = rand.below(count) as usize;
        }
        Ok(self.mutation_by_idx(idx))
    }

    /// New default implementation for mutate
    /// Implementations must forward mutate() to this method
    fn scheduled_mutate(
        &mut self,
        rand: &mut R,
        corpus: &mut C,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<(), AflError> {
        let num = self.iterations(rand, input);
        for _ in 0..num {
            self.schedule(rand, input)?(self, rand, corpus, input)?;
        }
        Ok(())
    }
}

pub struct StdScheduledMutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    mutations: Vec<MutationFunction<Self, C, I, R>>,
}

impl<C, I, R> Mutator<C, I, R> for StdScheduledMutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn mutate(
        &mut self,
        rand: &mut R,
        corpus: &mut C,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<(), AflError> {
        self.scheduled_mutate(rand, corpus, input, _stage_idx)
    }
}

impl<C, I, R> ComposedByMutations<C, I, R> for StdScheduledMutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn mutation_by_idx(&self, index: usize) -> MutationFunction<Self, C, I, R> {
        self.mutations[index]
    }

    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

    fn add_mutation(&mut self, mutation: MutationFunction<Self, C, I, R>) {
        self.mutations.push(mutation)
    }
}

impl<C, I, R> ScheduledMutator<C, I, R> for StdScheduledMutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    // Just use the default methods
}

impl<C, I, R> StdScheduledMutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Create a new StdScheduledMutator instance without mutations and corpus
    pub fn new() -> Self {
        StdScheduledMutator { mutations: vec![] }
    }

    /// Create a new StdScheduledMutator instance specifying mutations
    pub fn with_mutations(mutations: Vec<MutationFunction<Self, C, I, R>>) -> Self {
        StdScheduledMutator {
            mutations: mutations,
        }
    }
}

/// Bitflip mutation for inputs with a bytes vector
pub fn mutation_bitflip<M, C, I, R>(
    _mutator: &mut M,
    rand: &mut R,
    _corpus: &mut C,
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
    _corpus: &mut C,
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
    _corpus: &mut C,
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
    _corpus: &mut C,
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
    corpus: &mut C,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    // We don't want to use the testcase we're already using for splicing
    let (other_rr, _) = corpus.random_entry(rand)?.clone();
    let mut other_testcase = match other_rr.try_borrow_mut() {
        Ok(x) => x,
        Err(_) => {
            return Ok(MutationResult::Skipped);
        }
    };

    let other = other_testcase.load_input()?;
    // println!("Input: {:?}, other input: {:?}", input.bytes(), other.bytes());

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

/// Schedule some selected byte level mutations given a ScheduledMutator type
pub struct HavocBytesMutator<SM, C, I, R>
where
    SM: ScheduledMutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    scheduled: SM,
    phantom: PhantomData<(I, R, C)>,
}

impl<SM, C, I, R> Mutator<C, I, R> for HavocBytesMutator<SM, C, I, R>
where
    SM: ScheduledMutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    /// Mutate bytes
    fn mutate(
        &mut self,
        rand: &mut R,
        corpus: &mut C,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<(), AflError> {
        self.scheduled.mutate(rand, corpus, input, stage_idx)
    }
}

impl<SM, C, I, R> HavocBytesMutator<SM, C, I, R>
where
    SM: ScheduledMutator<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    /// Create a new HavocBytesMutator instance given a ScheduledMutator to wrap
    pub fn new(mut scheduled: SM) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        //scheduled.add_mutation(mutation_splice);
        HavocBytesMutator {
            scheduled: scheduled,
            phantom: PhantomData,
        }
    }
}

impl<C, I, R> HavocBytesMutator<StdScheduledMutator<C, I, R>, C, I, R>
where
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    /// Create a new HavocBytesMutator instance wrapping StdScheduledMutator
    pub fn new_default() -> Self {
        let mut scheduled = StdScheduledMutator::<C, I, R>::new();
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);

        scheduled.add_mutation(mutation_byteflip);
        scheduled.add_mutation(mutation_byteinc);
        scheduled.add_mutation(mutation_bytedec);
        scheduled.add_mutation(mutation_splice);
        HavocBytesMutator {
            scheduled: scheduled,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::inputs::BytesInput;
    use crate::mutators::scheduled::{mutation_splice, StdScheduledMutator};
    use crate::utils::{Rand, XKCDRand};
    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        inputs::HasBytesVec,
    };

    #[test]
    fn test_mut_splice() {
        // With the current impl, seed of 1 will result in a split at pos 2.
        let mut rand = XKCDRand::new();
        let mut corpus: InMemoryCorpus<BytesInput, XKCDRand> = InMemoryCorpus::new();
        corpus.add(Testcase::new(vec!['a' as u8, 'b' as u8, 'c' as u8]).into());
        corpus.add(Testcase::new(vec!['d' as u8, 'e' as u8, 'f' as u8]).into());

        let (testcase_rr, _) = corpus
            .next(&mut rand)
            .expect("Corpus did not contain entries");
        let mut testcase = testcase_rr.borrow_mut();
        let mut input = testcase.load_input().expect("No input in testcase").clone();

        rand.set_seed(5);
        let mut mutator = StdScheduledMutator::new();

        mutation_splice(&mut mutator, &mut rand, &mut corpus, &mut input).unwrap();

        #[cfg(feature = "std")]
        println!("{:?}", input.bytes());

        // The pre-seeded rand should have spliced at position 2.
        // TODO: Maybe have a fixed rand for this purpose?
        assert_eq!(input.bytes(), &['a' as u8, 'b' as u8, 'f' as u8])
    }
}
