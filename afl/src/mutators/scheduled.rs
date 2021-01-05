use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::{
    inputs::{HasBytesVec, Input},
    mutators::{Corpus, *},
    utils::Rand,
    AflError,
};

pub trait ScheduledMutator<C, I, R>: Mutator<C, I, R> + ComposedByMutations<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Compute the number of iterations used to apply stacked mutations
    #[inline]
    fn iterations(&mut self, rand: &mut R, _input: &I) -> u64 {
        1 << (1 + rand.below(6))
    }

    /// Get the next mutation to apply
    #[inline]
    fn schedule(&mut self, mutations_count: usize, rand: &mut R, _input: &I) -> usize {
        debug_assert!(mutations_count > 0);
        rand.below(mutations_count as u64) as usize
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
            let idx = self.schedule(self.mutations_count(), rand, input);
            self.mutation_by_idx(idx)(self, rand, corpus, input)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
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
    #[inline]
    fn mutation_by_idx(&self, index: usize) -> MutationFunction<Self, C, I, R> {
        self.mutations[index]
    }

    #[inline]
    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

    #[inline]
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
    #[inline]
    fn max_size(&self) -> usize {
        self.max_size
    }

    #[inline]
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
        Self {
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

#[derive(Clone, Debug)]
/// Schedule some selected byte level mutations given a ScheduledMutator type
pub struct HavocBytesMutator<SM, C, I, R>
where
    SM: ScheduledMutator<C, I, R> + HasMaxSize,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    scheduled: SM,
    phantom: PhantomData<(I, R, C)>,
}

impl<SM, C, I, R> Mutator<C, I, R> for HavocBytesMutator<SM, C, I, R>
where
    SM: ScheduledMutator<C, I, R> + HasMaxSize,
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
        _stage_idx: i32,
    ) -> Result<(), AflError> {
        //self.scheduled.mutate(rand, corpus, input, stage_idx);
        let num = self.scheduled.iterations(rand, input);
        for _ in 0..num {
            let idx = self.scheduled.schedule(13, rand, input);
            match idx {
                0 => mutation_bitflip(self, rand, corpus, input)?,
                1 => mutation_byteflip(self, rand, corpus, input)?,
                2 => mutation_byteinc(self, rand, corpus, input)?,
                3 => mutation_bytedec(self, rand, corpus, input)?,
                4 => mutation_byteneg(self, rand, corpus, input)?,
                5 => mutation_byterand(self, rand, corpus, input)?,

                6 => mutation_byteadd(self, rand, corpus, input)?,
                7 => mutation_wordadd(self, rand, corpus, input)?,
                8 => mutation_dwordadd(self, rand, corpus, input)?,
                9 => mutation_byteinteresting(self, rand, corpus, input)?,
                10 => mutation_wordinteresting(self, rand, corpus, input)?,
                11 => mutation_dwordinteresting(self, rand, corpus, input)?,

                _ => mutation_splice(self, rand, corpus, input)?,
            };
        }
        Ok(())
    }
}

impl<SM, C, I, R> HasMaxSize for HavocBytesMutator<SM, C, I, R>
where
    SM: ScheduledMutator<C, I, R> + HasMaxSize,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    #[inline]
    fn max_size(&self) -> usize {
        self.scheduled.max_size()
    }

    #[inline]
    fn set_max_size(&mut self, max_size: usize) {
        self.scheduled.set_max_size(max_size);
    }
}

impl<SM, C, I, R> HavocBytesMutator<SM, C, I, R>
where
    SM: ScheduledMutator<C, I, R> + HasMaxSize,
    C: Corpus<I, R>,
    I: Input + HasBytesVec,
    R: Rand,
{
    /// Create a new HavocBytesMutator instance given a ScheduledMutator to wrap
    pub fn new(mut scheduled: SM) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_splice);
        Self {
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
        scheduled.add_mutation(mutation_byterand);

        scheduled.add_mutation(mutation_byteadd);
        scheduled.add_mutation(mutation_wordadd);
        scheduled.add_mutation(mutation_dwordadd);
        scheduled.add_mutation(mutation_qwordadd);
        scheduled.add_mutation(mutation_byteinteresting);
        scheduled.add_mutation(mutation_wordinteresting);
        scheduled.add_mutation(mutation_dwordinteresting);

        /*scheduled.add_mutation(mutation_bytesdelete);
        scheduled.add_mutation(mutation_bytesdelete);
        scheduled.add_mutation(mutation_bytesdelete);
        scheduled.add_mutation(mutation_bytesdelete);
        scheduled.add_mutation(mutation_bytesexpand);
        scheduled.add_mutation(mutation_bytesinsert);
        scheduled.add_mutation(mutation_bytesrandinsert);
        scheduled.add_mutation(mutation_bytesset);
        scheduled.add_mutation(mutation_bytesrandset);
        scheduled.add_mutation(mutation_bytescopy);
        scheduled.add_mutation(mutation_bytesswap);*/

        // TODO dictionary and custom dictionary (redqueen etc.)
        /*scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_bitflip);*/

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
        let mut input = testcase.borrow_mut().load_input().unwrap().clone();

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
