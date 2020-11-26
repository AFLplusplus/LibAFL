use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::inputs::{HasBytesVec, Input};
use crate::mutators::Corpus;
use crate::mutators::*;
use crate::utils::Rand;
use crate::AflError;

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
        corpus: &C,
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
    max_size: usize,
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
        corpus: &C,
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

impl<C, I, R> HasMaxSize for StdScheduledMutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn max_size(&self) -> usize {
        self.max_size
    }
    fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
    }
}

impl<C, I, R> StdScheduledMutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Create a new StdScheduledMutator instance without mutations and corpus
    pub fn new() -> Self {
        StdScheduledMutator {
            mutations: vec![],
            max_size: DEFAULT_MAX_SIZE,
        }
    }

    /// Create a new StdScheduledMutator instance specifying mutations
    pub fn with_mutations(mutations: Vec<MutationFunction<Self, C, I, R>>) -> Self {
        StdScheduledMutator {
            mutations: mutations,
            max_size: DEFAULT_MAX_SIZE,
        }
    }
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
        corpus: &C,
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
        scheduled.add_mutation(mutation_splice);
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
        scheduled.add_mutation(mutation_byteflip);
        scheduled.add_mutation(mutation_byteinc);
        scheduled.add_mutation(mutation_bytedec);
        scheduled.add_mutation(mutation_byteneg);

        //scheduled.add_mutation(mutation_bytesexpand);
        //scheduled.add_mutation(mutation_bytesdelete);
        //scheduled.add_mutation(mutation_bytesdelete);
        //scheduled.add_mutation(mutation_bytesdelete);
        //scheduled.add_mutation(mutation_bytesdelete);

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
    use crate::mutators::scheduled::StdScheduledMutator;
    use crate::utils::{Rand, XKCDRand};
    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        inputs::HasBytesVec,
    };

    use super::mutation_splice;

    #[test]
    fn test_mut_splice() {
        // With the current impl, seed of 1 will result in a split at pos 2.
        let mut rand = XKCDRand::new();
        let mut corpus: InMemoryCorpus<BytesInput, XKCDRand> = InMemoryCorpus::new();
        corpus.add(Testcase::new(vec!['a' as u8, 'b' as u8, 'c' as u8]).into());
        corpus.add(Testcase::new(vec!['d' as u8, 'e' as u8, 'f' as u8]).into());

        let (testcase, _) = corpus
            .next(&mut rand)
            .expect("Corpus did not contain entries");
        let mut input = testcase.input().as_ref().unwrap().clone();

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
