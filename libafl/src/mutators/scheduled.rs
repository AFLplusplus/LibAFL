//! The `ScheduledMutator` schedules multiple mutations internally.

use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};
use serde::{Deserialize, Serialize};

use crate::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, tuple_list_type, NamedTuple},
        AsSlice,
    },
    corpus::Corpus,
    inputs::{HasBytesVec, Input},
    mutators::{MutationResult, Mutator, MutatorsTuple},
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand},
    Error,
};

pub use crate::mutators::mutations::*;
pub use crate::mutators::token_mutations::*;

/// The metadata placed in a [`crate::corpus::Testcase`] by a [`LoggerScheduledMutator`].
#[derive(Serialize, Deserialize)]
pub struct LogMutationMetadata {
    /// A list of logs
    pub list: Vec<String>,
}

crate::impl_serdeany!(LogMutationMetadata);

impl AsSlice<String> for LogMutationMetadata {
    fn as_slice(&self) -> &[String] {
        self.list.as_slice()
    }
}

impl LogMutationMetadata {
    /// Creates new [`struct@LogMutationMetadata`].
    #[must_use]
    pub fn new(list: Vec<String>) -> Self {
        Self { list }
    }
}

/// A [`Mutator`] that composes multiple mutations into one.
pub trait ComposedByMutations<I, MT, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
{
    /// Get the mutations
    fn mutations(&self) -> &MT;

    /// Get the mutations (mut)
    fn mutations_mut(&mut self) -> &mut MT;
}

/// A [`Mutator`] scheduling multiple [`Mutator`]s for an input.
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

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
pub struct StdScheduledMutator<I, MT, R, S>
where
    I: Input,
    MT: MutatorsTuple<I, S>,
    R: Rand,
    S: HasRand<R>,
{
    mutations: MT,
    max_iterations: u64,
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
        1 << (1 + state.rand_mut().below(self.max_iterations))
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
    /// Create a new [`StdScheduledMutator`] instance specifying mutations
    pub fn new(mutations: MT) -> Self {
        StdScheduledMutator {
            mutations,
            max_iterations: 6,
            phantom: PhantomData,
        }
    }

    /// Create a new [`StdScheduledMutator`] instance specifying mutations and the maximun number of iterations
    pub fn with_max_iterations(mutations: MT, max_iterations: u64) -> Self {
        StdScheduledMutator {
            mutations,
            max_iterations,
            phantom: PhantomData,
        }
    }
}

/// Get the mutations that compose the Havoc mutator
#[must_use]
pub fn havoc_mutations<C, I, R, S>() -> tuple_list_type!(
       BitFlipMutator<I, R, S>,
       ByteFlipMutator<I, R, S>,
       ByteIncMutator<I, R, S>,
       ByteDecMutator<I, R, S>,
       ByteNegMutator<I, R, S>,
       ByteRandMutator<I, R, S>,
       ByteAddMutator<I, R, S>,
       WordAddMutator<I, R, S>,
       DwordAddMutator<I, R, S>,
       QwordAddMutator<I, R, S>,
       ByteInterestingMutator<I, R, S>,
       WordInterestingMutator<I, R, S>,
       DwordInterestingMutator<I, R, S>,
       BytesDeleteMutator<I, R, S>,
       BytesDeleteMutator<I, R, S>,
       BytesDeleteMutator<I, R, S>,
       BytesDeleteMutator<I, R, S>,
       BytesExpandMutator<I, R, S>,
       BytesInsertMutator<I, R, S>,
       BytesRandInsertMutator<I, R, S>,
       BytesSetMutator<I, R, S>,
       BytesRandSetMutator<I, R, S>,
       BytesCopyMutator<I, R, S>,
       BytesInsertCopyMutator<I, R, S>,
       BytesSwapMutator<I, R, S>,
       CrossoverInsertMutator<C, I, R, S>,
       CrossoverReplaceMutator<C, I, R, S>,
   )
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
        BytesInsertCopyMutator::new(),
        BytesSwapMutator::new(),
        CrossoverInsertMutator::new(),
        CrossoverReplaceMutator::new(),
    )
}

/// Get the mutations that uses the Tokens metadata
#[must_use]
pub fn tokens_mutations<C, I, R, S>(
) -> tuple_list_type!(TokenInsert<I, R, S>, TokenReplace<I, R, S>)
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
    C: Corpus<I>,
    R: Rand,
{
    tuple_list!(TokenInsert::new(), TokenReplace::new(),)
}

/// A logging [`Mutator`] that wraps around a [`StdScheduledMutator`].
pub struct LoggerScheduledMutator<C, I, MT, R, S, SM>
where
    C: Corpus<I>,
    I: Input,
    MT: MutatorsTuple<I, S> + NamedTuple,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
    SM: ScheduledMutator<I, MT, S>,
{
    scheduled: SM,
    mutation_log: Vec<usize>,
    phantom: PhantomData<(C, I, MT, R, S)>,
}

impl<C, I, MT, R, S, SM> Debug for LoggerScheduledMutator<C, I, MT, R, S, SM>
where
    C: Corpus<I>,
    I: Input,
    MT: MutatorsTuple<I, S> + NamedTuple,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
    SM: ScheduledMutator<I, MT, S>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LoggerScheduledMutator with {} mutations for Input type {}",
            self.scheduled.mutations().len(),
            core::any::type_name::<I>()
        )
    }
}

impl<C, I, MT, R, S, SM> Mutator<I, S> for LoggerScheduledMutator<C, I, MT, R, S, SM>
where
    C: Corpus<I>,
    I: Input,
    MT: MutatorsTuple<I, S> + NamedTuple,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
    SM: ScheduledMutator<I, MT, S>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        if let Some(idx) = corpus_idx {
            let mut testcase = (*state.corpus_mut().get(idx)?).borrow_mut();
            let mut log = Vec::<String>::new();
            while let Some(idx) = self.mutation_log.pop() {
                let name = String::from(self.scheduled.mutations().name(idx).unwrap()); // TODO maybe return an Error on None
                log.push(name);
            }
            let meta = LogMutationMetadata::new(log);
            testcase.add_metadata(meta);
        };
        // Always reset the log for each run
        self.mutation_log.clear();
        Ok(())
    }
}

impl<C, I, MT, R, S, SM> ComposedByMutations<I, MT, S>
    for LoggerScheduledMutator<C, I, MT, R, S, SM>
where
    C: Corpus<I>,
    I: Input,
    MT: MutatorsTuple<I, S> + NamedTuple,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
    SM: ScheduledMutator<I, MT, S>,
{
    #[inline]
    fn mutations(&self) -> &MT {
        self.scheduled.mutations()
    }

    #[inline]
    fn mutations_mut(&mut self) -> &mut MT {
        self.scheduled.mutations_mut()
    }
}

impl<C, I, MT, R, S, SM> ScheduledMutator<I, MT, S> for LoggerScheduledMutator<C, I, MT, R, S, SM>
where
    C: Corpus<I>,
    I: Input,
    MT: MutatorsTuple<I, S> + NamedTuple,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
    SM: ScheduledMutator<I, MT, S>,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(6))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> usize {
        debug_assert!(!self.scheduled.mutations().is_empty());
        state
            .rand_mut()
            .below(self.scheduled.mutations().len() as u64) as usize
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let num = self.iterations(state, input);
        self.mutation_log.clear();
        for _ in 0..num {
            let idx = self.schedule(state, input);
            self.mutation_log.push(idx);
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

impl<C, I, MT, R, S, SM> LoggerScheduledMutator<C, I, MT, R, S, SM>
where
    C: Corpus<I>,
    I: Input,
    MT: MutatorsTuple<I, S> + NamedTuple,
    R: Rand,
    S: HasRand<R> + HasCorpus<C, I>,
    SM: ScheduledMutator<I, MT, S>,
{
    /// Create a new [`StdScheduledMutator`] instance without mutations and corpus
    pub fn new(scheduled: SM) -> Self {
        Self {
            scheduled,
            mutation_log: vec![],
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        bolts::rands::{Rand, StdRand, XkcdRand},
        corpus::{Corpus, InMemoryCorpus, Testcase},
        inputs::{BytesInput, HasBytesVec},
        mutators::{
            mutations::SpliceMutator,
            scheduled::{havoc_mutations, StdScheduledMutator},
            Mutator,
        },
        state::StdState,
    };

    #[test]
    fn test_mut_scheduled() {
        // With the current impl, seed of 1 will result in a split at pos 2.
        let mut rand = XkcdRand::with_seed(5);
        let mut corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
        corpus.add(Testcase::new(vec![b'a', b'b', b'c'])).unwrap();
        corpus.add(Testcase::new(vec![b'd', b'e', b'f'])).unwrap();

        let testcase = corpus.get(0).expect("Corpus did not contain entries");
        let mut input = testcase.borrow_mut().load_input().unwrap().clone();

        let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());

        rand.set_seed(5);

        let mut splice = SpliceMutator::new();
        splice.mutate(&mut state, &mut input, 0).unwrap();

        #[cfg(feature = "std")]
        println!("{:?}", input.bytes());

        // The pre-seeded rand should have spliced at position 2.
        // TODO: Maybe have a fixed rand for this purpose?
        assert_eq!(input.bytes(), &[b'a', b'b', b'f']);
    }

    #[test]
    fn test_havoc() {
        // With the current impl, seed of 1 will result in a split at pos 2.
        let rand = StdRand::with_seed(0x1337);
        let mut corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
        corpus.add(Testcase::new(vec![b'a', b'b', b'c'])).unwrap();
        corpus.add(Testcase::new(vec![b'd', b'e', b'f'])).unwrap();

        let testcase = corpus.get(0).expect("Corpus did not contain entries");
        let mut input = testcase.borrow_mut().load_input().unwrap().clone();
        let input_prior = input.clone();

        let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());

        let mut havoc = StdScheduledMutator::new(havoc_mutations());

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
