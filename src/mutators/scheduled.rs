use crate::inputs::{HasBytesVec, Input};
use crate::mutators::Mutator;
use crate::mutators::{Corpus, HasCorpus};
use crate::utils::{HasRand, Rand};
use crate::AflError;

use alloc::vec::Vec;
use core::marker::PhantomData;

pub enum MutationResult {
    Mutated,
    Skipped,
}

// TODO maybe the mutator arg is not needed
/// The generic function type that identifies mutations
type MutationFunction<M, S, I> = fn(&mut M, &mut S, &mut I) -> Result<MutationResult, AflError>;

pub trait ComposedByMutations<S, C, I, R>
where
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Get a mutation by index
    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<Self, S, I>, AflError>;

    /// Get the number of mutations
    fn mutations_count(&self) -> usize;

    /// Add a mutation
    fn add_mutation(&mut self, mutation: MutationFunction<Self, S, I>);
}

pub trait ScheduledMutator<S, C, I, R>:
    Mutator<S, C, I, R> + ComposedByMutations<S, C, I, R>
where
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&mut self, rand: &mut R, _input: &I) -> u64 {
        1 << (1 + rand.below(7))
    }

    /// Get the next mutation to apply
    fn schedule(
        &mut self,
        rand: &mut R,
        _input: &I,
    ) -> Result<MutationFunction<Self, S, I>, AflError> {
        let count = self.mutations_count() as u64;
        if count == 0 {
            return Err(AflError::Empty("no mutations".into()));
        }
        let idx;
        {
            idx = rand.below(count) as usize;
        }
        self.mutation_by_idx(idx)
    }

    /// New default implementation for mutate
    /// Implementations must forward mutate() to this method
    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<(), AflError> {
        let num = self.iterations(state.rand_mut(), input);
        for _ in 0..num {
            self.schedule(state.rand_mut(), input)?(self, state, input)?;
        }
        Ok(())
    }
}

pub struct DefaultScheduledMutator<S, C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    mutations: Vec<MutationFunction<Self, S, I>>,
}

impl<S, C, I, R> Mutator<S, C, I, R> for DefaultScheduledMutator<S, C, I, R>
where
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn mutate(&mut self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<(), AflError> {
        self.scheduled_mutate(state, input, _stage_idx)
    }
}

impl<S, C, I, R> ComposedByMutations<S, C, I, R> for DefaultScheduledMutator<S, C, I, R>
where
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<Self, S, I>, AflError> {
        if index >= self.mutations.len() {
            return Err(AflError::Unknown("oob".into()));
        }
        Ok(self.mutations[index])
    }

    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

    fn add_mutation(&mut self, mutation: MutationFunction<Self, S, I>) {
        self.mutations.push(mutation)
    }
}

impl<S, C, I, R> ScheduledMutator<S, C, I, R> for DefaultScheduledMutator<S, C, I, R>
where
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    // Just use the default methods
}

impl<S, C, I, R> DefaultScheduledMutator<S, C, I, R>
where
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Create a new DefaultScheduledMutator instance without mutations and corpus
    pub fn new() -> Self {
        DefaultScheduledMutator { mutations: vec![] }
    }

    /// Create a new DefaultScheduledMutator instance specifying mutations and corpus too
    pub fn new_all(mutations: Vec<MutationFunction<Self, S, I>>) -> Self {
        DefaultScheduledMutator {
            mutations: mutations,
        }
    }
}

/// Bitflip mutation for inputs with a bytes vector
pub fn mutation_bitflip<M, S, C, R, I>(
    mutator: &mut M,
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<S, C, I, R>,
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    let bit = state.rand_mut().below((input.bytes().len() * 8) as u64) as usize;
    input.bytes_mut()[bit >> 3] ^= (128 >> (bit & 7)) as u8;
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
pub fn mutation_splice<M, S, C, R, I>(
    mutator: &mut M,
    state: &mut S,
    input: &mut I,
) -> Result<MutationResult, AflError>
where
    M: Mutator<S, C, I, R>,
    S: HasRand<R> + HasCorpus<C, I, R>,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    let mut retry_count = 0;
    // We don't want to use the testcase we're already using for splicing
    let other_rr = loop {
        let mut found = false;
        let (other_rr, _) = state.corpus_mut().random_entry(state.rand_mut())?.clone();
        match other_rr.try_borrow_mut() {
            Ok(_) => found = true,
            Err(_) => {
                if retry_count == 20 {
                    return Ok(MutationResult::Skipped);
                }
                retry_count += 1;
            }
        };
        if found {
            break other_rr;
        }
    };
    // This should work now, as we successfully try_borrow_mut'd before.
    let mut other_testcase = other_rr.borrow_mut();
    let other = other_testcase.load_input()?;
    // println!("Input: {:?}, other input: {:?}", input.bytes(), other.bytes());

    let mut counter = 0;
    let (first_diff, last_diff) = loop {
        let (f, l) = locate_diffs(input.bytes(), other.bytes());
        // println!("Diffs were between {} and {}", f, l);
        if f != l && f >= 0 && l >= 2 {
            break (f, l);
        }
        if counter == 20 {
            return Ok(MutationResult::Skipped);
        }
        counter += 1;
    };

    let split_at = rand.between(first_diff as u64, last_diff as u64) as usize;

    // println!("Splicing at {}", split_at);

    let _: Vec<_> = input
        .bytes_mut()
        .splice(split_at.., other.bytes()[split_at..].iter().cloned())
        .collect();

    // println!("Splice result: {:?}, input is now: {:?}", split_result, input.bytes());

    Ok(MutationResult::Mutated)
}

/// Schedule some selected byte level mutations given a ScheduledMutator type
pub struct HavocBytesMutator<C, I, SM, R>
where
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    SM: ScheduledMutator<C, I, R>,
    R: Rand,
{
    scheduled: SM,
    phantom: PhantomData<(I, R)>,
    _phantom_corpus: PhantomData<C>,
}

impl<C, I, SM, R> Mutator<C, I, R> for HavocBytesMutator<C, I, SM, R>
where
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    SM: ScheduledMutator<C, I, R>,
    R: Rand,
{
    /// Mutate bytes
    fn mutate(
        &mut self,
        corpus: &mut C,
        rand: &mut R,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<(), AflError> {
        self.scheduled.mutate(corpus, rand, input, stage_idx)
    }
}

impl<C, I, SM, R> HavocBytesMutator<C, I, SM, R>
where
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    SM: ScheduledMutator<C, I, R>,
    R: Rand,
{
    /// Create a new HavocBytesMutator instance given a ScheduledMutator to wrap
    pub fn new(mut scheduled: SM) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_splice);
        HavocBytesMutator {
            scheduled: scheduled,
            phantom: PhantomData,
            _phantom_corpus: PhantomData,
        }
    }
}

impl<C, I, R> HavocBytesMutator<C, I, DefaultScheduledMutator<C, I, R>, R>
where
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    /// Create a new HavocBytesMutator instance wrapping DefaultScheduledMutator
    pub fn new_default() -> Self {
        let mut scheduled = DefaultScheduledMutator::<C, I, R>::new();
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_splice);
        HavocBytesMutator {
            scheduled: scheduled,
            phantom: PhantomData,
            _phantom_corpus: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::inputs::BytesInput;
    use crate::mutators::scheduled::{mutation_splice, DefaultScheduledMutator};
    use crate::utils::{Rand, XKCDRand};
    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        inputs::HasBytesVec,
    };

    #[test]
    fn test_mut_splice() {
        // With the current impl, seed of 1 will result in a split at pos 2.
        let mut rand = XKCDRand::new();
        let mut corpus: InMemoryCorpus<BytesInput, _> = InMemoryCorpus::new();
        corpus.add(Testcase::new(vec!['a' as u8, 'b' as u8, 'c' as u8]).into());
        corpus.add(Testcase::new(vec!['d' as u8, 'e' as u8, 'f' as u8]).into());

        let (testcase_rr, _) = corpus
            .next(&mut rand)
            .expect("Corpus did not contain entries");
        let mut testcase = testcase_rr.borrow_mut();
        let mut input = testcase.load_input().expect("No input in testcase").clone();

        rand.set_seed(5);
        let mut mutator =
            DefaultScheduledMutator::<InMemoryCorpus<_, _>, BytesInput, XKCDRand>::new();

        mutation_splice(&mut mutator, &mut corpus, &mut rand, &mut input).unwrap();

        #[cfg(feature = "std")]
        println!("{:?}", input.bytes());

        // The pre-seeded rand should have spliced at position 2.
        // TODO: Maybe have a fixed rand for this purpose?
        assert_eq!(input.bytes(), &['a' as u8, 'b' as u8, 'f' as u8])
    }
}
