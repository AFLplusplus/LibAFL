extern crate alloc;
use crate::inputs::{HasBytesVec, Input};
use crate::mutators::Corpus;
use crate::mutators::Mutator;
use crate::utils::{HasRand, Rand};
use crate::AflError;

use alloc::rc::Rc;
use core::cell::RefCell;
use core::marker::PhantomData;

/// The generic function type that identifies mutations
type MutationFunction<C, M, I> = fn(&mut M, &mut C, &mut I) -> Result<(), AflError>;

pub trait ComposedByMutations<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    /// Get a mutation by index
    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<C, Self, I>, AflError>;

    /// Get the number of mutations
    fn mutations_count(&self) -> usize;

    /// Add a mutation
    fn add_mutation(&mut self, mutation: MutationFunction<C, Self, I>);
}

pub trait ScheduledMutator<C, I>: Mutator<C, I> + ComposedByMutations<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&mut self, _input: &I) -> u64 {
        1 << (1 + self.rand_below(7))
    }

    /// Get the next mutation to apply
    fn schedule(&mut self, _input: &I) -> Result<MutationFunction<C, Self, I>, AflError> {
        let count = self.mutations_count() as u64;
        if count == 0 {
            return Err(AflError::Empty("no mutations".to_string()));
        }
        let idx;
        {
            idx = self.rand_below(count) as usize;
        }
        self.mutation_by_idx(idx)
    }

    /// New default implementation for mutate
    /// Implementations must forward mutate() to this method
    fn scheduled_mutate(
        &mut self,
        corpus: &mut C,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<(), AflError> {
        let num = self.iterations(input);
        for _ in 0..num {
            self.schedule(input)?(self, corpus, input)?;
        }
        Ok(())
    }
}

pub struct DefaultScheduledMutator<'a, C, I, R>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    rand: Rc<RefCell<R>>,
    mutations: Vec<MutationFunction<C, Self, I>>,
}

impl<'a, C, I, R> HasRand for DefaultScheduledMutator<'_, C, I, R>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        &self.rand
    }
}

impl<'a, C, I, R> Mutator<C, I> for DefaultScheduledMutator<'_, C, I, R>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    fn mutate(&mut self, corpus: &mut C, input: &mut I, _stage_idx: i32) -> Result<(), AflError> {
        self.scheduled_mutate(corpus, input, _stage_idx)
    }
}

impl<'a, C, I, R> ComposedByMutations<C, I> for DefaultScheduledMutator<'_, C, I, R>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<C, Self, I>, AflError> {
        if index >= self.mutations.len() {
            return Err(AflError::Unknown("oob".to_string()));
        }
        Ok(self.mutations[index])
    }

    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

    fn add_mutation(&mut self, mutation: MutationFunction<C, Self, I>) {
        self.mutations.push(mutation)
    }
}

impl<'a, C, I, R> ScheduledMutator<C, I> for DefaultScheduledMutator<'_, C, I, R>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    // Just use the default methods
}

impl<'a, C, I, R> DefaultScheduledMutator<'a, C, I, R>
where
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    /// Create a new DefaultScheduledMutator instance without mutations and corpus
    pub fn new(rand: &Rc<RefCell<R>>) -> Self {
        DefaultScheduledMutator {
            rand: Rc::clone(rand),
            mutations: vec![],
        }
    }

    /// Create a new DefaultScheduledMutator instance specifying mutations and corpus too
    pub fn new_all(rand: &Rc<RefCell<R>>, mutations: Vec<MutationFunction<C, Self, I>>) -> Self {
        DefaultScheduledMutator {
            rand: Rc::clone(rand),
            mutations: mutations,
        }
    }
}

/// Bitflip mutation for inputs with a bytes vector
pub fn mutation_bitflip<C, M, I>(
    mutator: &mut M,
    _corpus: &mut C,
    input: &mut I,
) -> Result<(), AflError>
where
    C: Corpus<I>,
    M: HasRand,
    I: Input + HasBytesVec,
{
    let bit = mutator.rand_below(input.bytes().len() as u64) as usize;
    input.bytes_mut()[bit >> 3] ^= (128 >> (bit & 7)) as u8;
    Ok(())
}

/// Returns the first and last diff position between the given vectors, stopping at the min len
fn locate_diffs(this: &Vec<u8>, other: &Vec<u8>) -> (i64, i64) {
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
pub fn mutation_splice<C, M, I>(
    mutator: &mut M,
    corpus: &mut C,
    input: &mut I,
) -> Result<(), AflError>
where
    C: Corpus<I>,
    M: HasRand,
    I: Input + HasBytesVec,
{
    let mut retry_count = 0;
    // We don't want to use the testcase we're already using for splicing
    let other_rr = loop {
        let mut found = false;
        let other_rr = corpus.random_entry()?.clone();
        match other_rr.try_borrow_mut() {
            Ok(_) => found = true,
            Err(_) => {
                if retry_count == 20 {
                    return Err(AflError::Empty("No suitable testcase found for splicing".to_owned()));
                }
                retry_count += 1;
            },
        };
        if found {
            break other_rr;
        }
    };
    // This should work now, as we successfully try_borrow_mut'd before.
    let mut other_testcase = other_rr.borrow_mut();
    let other = other_testcase.load_input()?;

    let mut counter = 0;
    let (first_diff, last_diff) = loop {
        let (f, l) = locate_diffs(input.bytes(), other.bytes());
        if f != l && f >= 0 && l >= 2 {
            break (f, l);
        }
        if counter == 20 {
            return Err(AflError::Empty("No valid diff found".to_owned()));
        }
        counter += 1;
    };

    let split_at = mutator.rand_between(first_diff as u64, last_diff as u64) as usize;

    let _: Vec<_> = input
        .bytes_mut()
        .splice(split_at.., other.bytes()[split_at..].iter().cloned())
        .collect();

    Ok(())
}

/// Schedule some selected byte level mutations given a ScheduledMutator type
pub struct HavocBytesMutator<C, I, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    S: ScheduledMutator<C, I>,
{
    scheduled: S,
    phantom: PhantomData<I>,
    _phantom_corpus: PhantomData<C>,
}

impl<C, I, S> HasRand for HavocBytesMutator<C, I, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    S: ScheduledMutator<C, I>,
{
    type R = S::R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        &self.scheduled.rand()
    }
}

impl<C, I, S> Mutator<C, I> for HavocBytesMutator<C, I, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    S: ScheduledMutator<C, I>,
{
    fn mutate(&mut self, corpus: &mut C, input: &mut I, stage_idx: i32) -> Result<(), AflError> {
        self.scheduled.mutate(corpus, input, stage_idx)
    }
}

impl<C, I, S> HavocBytesMutator<C, I, S>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    S: ScheduledMutator<C, I>,
{
    /// Create a new HavocBytesMutator instance given a ScheduledMutator to wrap
    pub fn new(mut scheduled: S) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        HavocBytesMutator {
            scheduled: scheduled,
            phantom: PhantomData,
            _phantom_corpus: PhantomData,
        }
    }
}

impl<'a, C, I, R> HavocBytesMutator<C, I, DefaultScheduledMutator<'a, C, I, R>>
where
    C: Corpus<I>,
    I: Input + HasBytesVec,
    R: Rand,
{
    /// Create a new HavocBytesMutator instance wrapping DefaultScheduledMutator
    pub fn new_default(rand: &Rc<RefCell<R>>) -> Self {
        let mut scheduled = DefaultScheduledMutator::<'a, C, I, R>::new(rand);
        scheduled.add_mutation(mutation_bitflip);
        HavocBytesMutator {
            scheduled: scheduled,
            phantom: PhantomData,
            _phantom_corpus: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::corpus::{Corpus, InMemoryCorpus};
    use crate::inputs::BytesInput;
    use crate::mutators::scheduled::mutation_splice;
    use crate::utils::{Xoshiro256StarRand, DefaultHasRand};

    #[test]
    fn test_mut_splice() {
        let rand = &Xoshiro256StarRand::new_rr(0);
        let mut has_rand = DefaultHasRand::new(&rand);
        let mut corpus = InMemoryCorpus::new(&rand);
        corpus.add_input(BytesInput::new(vec!['a' as u8, 'b' as u8, 'c' as u8]));
        corpus.add_input(BytesInput::new(vec!['d' as u8, 'e' as u8, 'f' as u8]));

        let testcase_rr = corpus.next().expect("Corpus did not contain entries");
        let mut testcase = testcase_rr.borrow_mut();
        let mut input = testcase.load_input().expect("No input in testcase").clone();

        mutation_splice(&mut has_rand, &mut corpus, &mut input).unwrap()

        // TODO: Finish testcase
    }
}
