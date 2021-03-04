use alloc::vec::Vec;
use core::{
    default::Default,
    fmt::{self, Debug},
    marker::PhantomData,
};

use crate::{
    corpus::Corpus,
    inputs::{HasBytesVec, Input},
    mutators::Mutator,
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
    utils::Rand,
    Error,
};

pub use crate::mutators::mutations::*;
pub use crate::mutators::token_mutations::*;

pub trait ScheduledMutator<I, S>: Mutator<I, S> + ComposedByMutations<I, S>
where
    I: Input,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, input: &I) -> u64;

    /// Get the next mutation to apply
    fn schedule(&self, mutations_count: usize, state: &mut S, input: &I) -> usize;

    /// New default implementation for mutate
    /// Implementations must forward mutate() to this method
    fn scheduled_mutate(&self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<(), Error> {
        let num = self.iterations(state, input);
        for _ in 0..num {
            let idx = self.schedule(self.mutations_count(), state, input);
            self.mutation_by_idx(idx)(state, input)?;
        }
        Ok(())
    }
}

pub struct StdScheduledMutator<I, R, S>
where
    I: Input,
    S: HasRand<R>,
    R: Rand,
{
    mutations: Vec<MutationFunction<I, S>>,
    phantom: PhantomData<R>,
}

impl<I, R, S> Debug for StdScheduledMutator<I, R, S>
where
    I: Input,
    S: HasRand<R>,
    R: Rand,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StdScheduledMutator with {} Mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, R, S> Mutator<I, S> for StdScheduledMutator<I, R, S>
where
    I: Input,
    S: HasRand<R>,
    R: Rand,
{
    fn mutate(&self, state: &mut S, input: &mut I, _stage_idx: i32) -> Result<(), Error> {
        self.scheduled_mutate(state, input, _stage_idx)
    }
}

impl<I, R, S> ComposedByMutations<I, S> for StdScheduledMutator<I, R, S>
where
    I: Input,
    S: HasRand<R>,
    R: Rand,
{
    #[inline]
    fn mutation_by_idx(&self, index: usize) -> MutationFunction<I, S> {
        self.mutations[index]
    }

    #[inline]
    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

    #[inline]
    fn add_mutation(&mut self, mutation: MutationFunction<I, S>) {
        self.mutations.push(mutation)
    }
}

impl<I, R, S> ScheduledMutator<I, S> for StdScheduledMutator<I, R, S>
where
    I: Input,
    S: HasRand<R>,
    R: Rand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(6))
    }

    /// Get the next mutation to apply
    fn schedule(&self, mutations_count: usize, state: &mut S, _: &I) -> usize {
        debug_assert!(mutations_count > 0);
        state.rand_mut().below(mutations_count as u64) as usize
    }
}

impl<I, R, S> StdScheduledMutator<I, R, S>
where
    I: Input,
    S: HasRand<R>,
    R: Rand,
{
    /// Create a new StdScheduledMutator instance without mutations and corpus
    pub fn new() -> Self {
        Self {
            mutations: vec![],
            phantom: PhantomData,
        }
    }

    /// Create a new StdScheduledMutator instance specifying mutations
    pub fn with_mutations(mutations: Vec<MutationFunction<I, S>>) -> Self {
        StdScheduledMutator {
            mutations,
            phantom: PhantomData,
        }
    }
}

impl<I, R, S> Default for StdScheduledMutator<I, R, S>
where
    I: Input,
    S: HasRand<R>,
    R: Rand,
{
    fn default() -> Self {
        Self::new()
    }
}

/// Schedule some selected byte level mutations given a ScheduledMutator type
#[derive(Clone, Debug)]
pub struct HavocBytesMutator<C, I, R, S, SM>
where
    SM: ScheduledMutator<I, S>,
    I: Input + HasBytesVec,
    S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
    C: Corpus<I>,
    R: Rand,
{
    scheduled: SM,
    phantom: PhantomData<(C, I, R, S)>,
}

impl<C, I, R, S, SM> Mutator<I, S> for HavocBytesMutator<C, I, R, S, SM>
where
    SM: ScheduledMutator<I, S>,
    I: Input + HasBytesVec,
    S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
    C: Corpus<I>,
    R: Rand,
{
    /// Mutate bytes
    fn mutate(&self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<(), Error> {
        self.scheduled.mutate(state, input, stage_idx)?;
        /*let num = self.scheduled.iterations(state, input);
        for _ in 0..num {
            let idx = self.scheduled.schedule(14, state, input);
            let mutation = match idx {
                0 => mutation_bitflip,
                1 => mutation_byteflip,
                2 => mutation_byteinc,
                3 => mutation_bytedec,
                4 => mutation_byteneg,
                5 => mutation_byterand,

                6 => mutation_byteadd,
                7 => mutation_wordadd,
                8 => mutation_dwordadd,
                9 => mutation_byteinteresting,
                10 => mutation_wordinteresting,
                11 => mutation_dwordinteresting,
                _ => mutation_splice,
            };
            mutation(self, state, input)?;
        }*/
        Ok(())
    }
}

impl<C, I, R, S, SM> HavocBytesMutator<C, I, R, S, SM>
where
    SM: ScheduledMutator<I, S>,
    I: Input + HasBytesVec,
    S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
    C: Corpus<I>,
    R: Rand,
{
    /// Create a new HavocBytesMutator instance given a ScheduledMutator to wrap
    pub fn new(mut scheduled: SM) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        scheduled.add_mutation(mutation_splice);
        Self {
            scheduled,
            phantom: PhantomData,
        }
    }
}

impl<C, I, R, S> Default for HavocBytesMutator<C, I, R, S, StdScheduledMutator<I, R, S>>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
    C: Corpus<I>,
    R: Rand,
{
    /// Create a new HavocBytesMutator instance wrapping StdScheduledMutator
    fn default() -> Self {
        let mut scheduled = StdScheduledMutator::<I, R, S>::new();
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

        scheduled.add_mutation(mutation_bytesdelete);
        scheduled.add_mutation(mutation_bytesdelete);
        scheduled.add_mutation(mutation_bytesdelete);
        scheduled.add_mutation(mutation_bytesdelete);
        scheduled.add_mutation(mutation_bytesexpand);
        scheduled.add_mutation(mutation_bytesinsert);
        scheduled.add_mutation(mutation_bytesrandinsert);
        scheduled.add_mutation(mutation_bytesset);
        scheduled.add_mutation(mutation_bytesrandset);
        scheduled.add_mutation(mutation_bytescopy);
        scheduled.add_mutation(mutation_bytesswap);

        scheduled.add_mutation(mutation_tokeninsert);
        scheduled.add_mutation(mutation_tokenreplace);

        scheduled.add_mutation(mutation_crossover_insert);
        scheduled.add_mutation(mutation_crossover_replace);
        //scheduled.add_mutation(mutation_splice);

        HavocBytesMutator {
            scheduled,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        inputs::{BytesInput, HasBytesVec},
        mutators::{
            scheduled::{mutation_splice, HavocBytesMutator, StdScheduledMutator},
            Mutator,
        },
        state::State,
        utils::{Rand, StdRand, XKCDRand},
    };

    #[test]
    fn test_mut_scheduled() {
        // With the current impl, seed of 1 will result in a split at pos 2.
        let mut rand = XKCDRand::with_seed(5);
        let mut corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
        corpus
            .add(Testcase::new(vec!['a' as u8, 'b' as u8, 'c' as u8]).into())
            .unwrap();
        corpus
            .add(Testcase::new(vec!['d' as u8, 'e' as u8, 'f' as u8]).into())
            .unwrap();

        let testcase = corpus.get(0).expect("Corpus did not contain entries");
        let mut input = testcase.borrow_mut().load_input().unwrap().clone();

        let mut state = State::new(rand, corpus, (), InMemoryCorpus::new(), ());

        rand.set_seed(5);

        mutation_splice(&mut state, &mut input).unwrap();

        #[cfg(feature = "std")]
        println!("{:?}", input.bytes());

        // The pre-seeded rand should have spliced at position 2.
        // TODO: Maybe have a fixed rand for this purpose?
        assert_eq!(input.bytes(), &['a' as u8, 'b' as u8, 'f' as u8])
    }

    #[test]
    fn test_havoc() {
        // With the current impl, seed of 1 will result in a split at pos 2.
        let rand = StdRand::with_seed(0x1337);
        let mut corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
        corpus
            .add(Testcase::new(vec!['a' as u8, 'b' as u8, 'c' as u8]).into())
            .unwrap();
        corpus
            .add(Testcase::new(vec!['d' as u8, 'e' as u8, 'f' as u8]).into())
            .unwrap();

        let testcase = corpus.get(0).expect("Corpus did not contain entries");
        let mut input = testcase.borrow_mut().load_input().unwrap().clone();
        let input_prior = input.clone();

        let mut state = State::new(rand, corpus, (), InMemoryCorpus::new(), ());

        let havoc = HavocBytesMutator::new(StdScheduledMutator::new());

        assert_eq!(input, input_prior);

        let mut equal_in_a_row = 0;

        for i in 0..42 {
            havoc.mutate(&mut state, &mut input, i).unwrap();

            // Make sure we actually mutate something, at least sometimes
            equal_in_a_row = if input == input_prior {
                equal_in_a_row + 1
            } else {
                0
            };
            assert_ne!(equal_in_a_row, 5);
        }
    }
}
