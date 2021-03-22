use alloc::vec::Vec;
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::tuples::tuple_list,
    corpus::Corpus,
    inputs::{HasBytesVec, Input},
    mutators::{MutationResult, Mutator, MutatorsTuple},
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
    utils::{AsSlice, Rand},
    Error,
};

pub use crate::mutators::mutations::*;
//pub use crate::mutators::token_mutations::*;

#[derive(Serialize, Deserialize)]
pub struct MutationsMetadata {
    pub list: Vec<usize>,
}

crate::impl_serdeany!(MutationsMetadata);

/*
impl AsSlice<usize> for MutationsMetadata {
    fn as_slice(&self) -> &[usize] {
        self.list.as_slice()
    }
}

impl MutationsMetadata {
    pub fn new(list: Vec<usize>) -> Self {
        Self { list }
    }
}

pub trait LogMutations {
    fn log_clear(&mut self);

    fn log_mutation(&mut self, mutation_type: MutationType);
}
*/

pub trait ComposedByMutations<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
{
    /// Get the mutations
    fn mutations(&self) -> &MT;

    // Get the mutations (mut)
    fn mutations_mut(&mut self) -> &mut MT;
}

pub trait ScheduledMutator<I, MT, S>: ComposedByMutations<I, MT, S> + Mutator<I, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, input: &I) -> u64;

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, input: &I) -> usize;

    /// New default implementation for mutate
    /// Implementations must forward mutate() to this method
    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let num = self.iterations(state, input);
        for _ in 0..num {
            let idx = self.schedule(state, input);
            let outcome = self
                .mutations_mut()
                .get_and_mutate(idx, state, input, stage_idx)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
        }
        Ok(r)
    }
}

pub struct StdScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    mutations: MT,
    phantom: PhantomData<(I, R, S)>,
}

impl<I, MT, R, S> Debug for StdScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StdScheduledMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, R, S> Mutator<I, S> for StdScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<I, MT, R, S> ComposedByMutations<I, MT, S> for StdScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    /// Get the mutations
    #[inline]
    fn mutations(&self) -> &MT {
        &self.mutations
    }

    // Get the mutations (mut)
    #[inline]
    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<I, MT, R, S> ScheduledMutator<I, MT, S> for StdScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(6))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> usize {
        debug_assert!(!self.mutations().is_empty());
        state.rand_mut().below(self.mutations().len() as u64) as usize
    }
}

impl<I, MT, R, S> StdScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    /// Create a new StdScheduledMutator instance specifying mutations
    pub fn new(mutations: MT) -> Self {
        StdScheduledMutator {
            mutations: mutations,
            phantom: PhantomData,
        }
    }
}

/// Get the mutations that compose the Havoc mutator
pub fn havoc_mutations<C, I, R, S>() -> impl MutatorsTuple<I, S>
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
    C: Corpus<I>,
    R: Rand,
{
    tuple_list!(
        BitFlipMutator::new(),
        //...
        // TODO complete this
        CrossoverReplaceMutator::new(),
    )
}

/*
pub struct StdScheduledMutator<C, I, R, S>
where
    I: Input,
    S: HasRand<R> + HasCorpus<C, I>,
    C: Corpus<I>,
    R: Rand,
{
    mutations: MT,
    mutation_log: Vec<usize>,
    phantom: PhantomData<(C, R)>,
}

impl<C, I, R, S> Debug for StdScheduledMutator<C, I, R, S>
where
    I: Input,
    S: HasRand<R> + HasCorpus<C, I>,
    C: Corpus<I>,
    R: Rand,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StdScheduledMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<I>()
        )
    }
}

impl<C, I, R, S> Mutator<I, S> for StdScheduledMutator<C, I, R, S>
where
    I: Input,
    S: HasRand<R> + HasCorpus<C, I>,
    C: Corpus<I>,
    R: Rand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, _stage_idx)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _is_interesting: u32,
        _stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        if let Some(idx) = corpus_idx {
            let mut testcase = (*state.corpus_mut().get(idx)?).borrow_mut();
            let meta = MutationsMetadata::new(core::mem::take(self.mutation_log.as_mut()));
            testcase.add_metadata(meta);
        };
        Ok(())
    }
}

impl<C, I, R, S> ComposedByMutations<I, S> for StdScheduledMutator<C, I, R, S>
where
    I: Input,
    S: HasRand<R> + HasCorpus<C, I>,
    C: Corpus<I>,
    R: Rand,
{
    #[inline]
    fn mutation_by_idx(&self, index: usize) -> (MutationFunction<I, S>, MutationType) {
        self.mutations[index]
    }

    #[inline]
    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

    #[inline]
    fn add_mutation(&mut self, mutation: (MutationFunction<I, S>, MutationType)) {
        self.mutations.push(mutation)
    }
}

impl<C, I, R, S> LogMutations for StdScheduledMutator<C, I, R, S>
where
    I: Input,
    S: HasRand<R> + HasCorpus<C, I>,
    C: Corpus<I>,
    R: Rand,
{
    #[inline]
    fn log_clear(&mut self) {
        self.mutation_log.clear();
    }

    #[inline]
    fn log_mutation(&mut self, mutation_type: MutationType) {
        self.mutation_log.push(mutation_type as usize)
    }
}

impl<C, I, R, S> ScheduledMutator<I, S> for StdScheduledMutator<C, I, R, S>
where
    I: Input,
    S: HasRand<R> + HasCorpus<C, I>,
    C: Corpus<I>,
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

impl<C, I, R, S> StdScheduledMutator<C, I, R, S>
where
    I: Input,
    S: HasRand<R> + HasCorpus<C, I>,
    C: Corpus<I>,
    R: Rand,
{
    /// Create a new StdScheduledMutator instance without mutations and corpus
    pub fn new() -> Self {
        Self {
            mutations: vec![],
            mutation_log: vec![],
            phantom: PhantomData,
        }
    }

    /// Create a new StdScheduledMutator instance specifying mutations
    pub fn with_mutations(mutations: Vec<(MutationFunction<I, S>, MutationType)>) -> Self {
        StdScheduledMutator {
            mutations,
            mutation_log: vec![],
            phantom: PhantomData,
        }
    }
}

impl<C, I, R, S> Default for StdScheduledMutator<C, I, R, S>
where
    I: Input,
    S: HasRand<R> + HasCorpus<C, I>,
    C: Corpus<I>,
    R: Rand,
{
    fn default() -> Self {
        Self::new()
    }
}
*/

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
