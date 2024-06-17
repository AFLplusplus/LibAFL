//! The `ScheduledMutator` schedules multiple mutations internally.

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use libafl_bolts::{
    rands::Rand,
    tuples::{tuple_list, tuple_list_type, Merge, NamedTuple},
    Named,
};
use serde::{Deserialize, Serialize};

use super::MutationId;
use crate::{
    corpus::{Corpus, CorpusId},
    mutators::{
        mutations::{
            BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
            ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator,
            BytesDeleteMutator, BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator,
            BytesRandInsertMutator, BytesRandSetMutator, BytesSetMutator, BytesSwapMutator,
            CrossoverInsertMutator, CrossoverReplaceMutator, DwordAddMutator,
            DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
        },
        token_mutations::{TokenInsert, TokenReplace},
        MutationResult, Mutator, MutatorsTuple,
    },
    state::{HasCorpus, HasRand},
    Error, HasMetadata,
};

/// The metadata placed in a [`crate::corpus::Testcase`] by a [`LoggerScheduledMutator`].
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub struct LogMutationMetadata {
    /// A list of logs
    pub list: Vec<Cow<'static, str>>,
}

libafl_bolts::impl_serdeany!(LogMutationMetadata);

impl Deref for LogMutationMetadata {
    type Target = [Cow<'static, str>];
    fn deref(&self) -> &[Cow<'static, str>] {
        &self.list
    }
}
impl DerefMut for LogMutationMetadata {
    #[must_use]
    fn deref_mut(&mut self) -> &mut [Cow<'static, str>] {
        &mut self.list
    }
}

impl LogMutationMetadata {
    /// Creates new [`struct@LogMutationMetadata`].
    #[must_use]
    pub fn new(list: Vec<Cow<'static, str>>) -> Self {
        Self { list }
    }
}

/// A [`Mutator`] that composes multiple mutations into one.
pub trait ComposedByMutations<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
{
    /// Get the mutations
    fn mutations(&self) -> &MT;

    /// Get the mutations (mutable)
    fn mutations_mut(&mut self) -> &mut MT;
}

/// A [`Mutator`] scheduling multiple [`Mutator`]s for an input.
pub trait ScheduledMutator<I, MT, S>: ComposedByMutations<I, MT, S> + Mutator<I, S>
where
    MT: MutatorsTuple<I, S>,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, input: &I) -> u64;

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, input: &I) -> MutationId;

    /// New default implementation for mutate.
    /// Implementations must forward `mutate()` to this method
    fn scheduled_mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let num = self.iterations(state, input);
        for _ in 0..num {
            let idx = self.schedule(state, input);
            let outcome = self.mutations_mut().get_and_mutate(idx, state, input)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
        }
        Ok(r)
    }
}

/// A [`Mutator`] that schedules one of the embedded mutations on each call.
pub struct StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    name: Cow<'static, str>,
    mutations: MT,
    max_stack_pow: usize,
    phantom: PhantomData<(I, S)>,
}

impl<I, MT, S> Debug for StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
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

impl<I, MT, S> Named for StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, MT, S> Mutator<I, S> for StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    #[inline]
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }
}

impl<I, MT, S> ComposedByMutations<I, MT, S> for StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Get the mutations
    #[inline]
    fn mutations(&self) -> &MT {
        &self.mutations
    }

    // Get the mutations (mutable)
    #[inline]
    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<I, MT, S> ScheduledMutator<I, MT, S> for StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(self.max_stack_pow))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(self.mutations.len() != 0);
        state.rand_mut().below(self.mutations.len()).into()
    }
}

impl<I, MT, S> StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    /// Create a new [`StdScheduledMutator`] instance specifying mutations
    pub fn new(mutations: MT) -> Self {
        StdScheduledMutator {
            name: Cow::from(format!(
                "StdScheduledMutator[{}]",
                mutations.names().join(", ")
            )),
            mutations,
            max_stack_pow: 7,
            phantom: PhantomData,
        }
    }

    /// Create a new [`StdScheduledMutator`] instance specifying mutations and the maximun number of iterations
    pub fn with_max_stack_pow(mutations: MT, max_stack_pow: usize) -> Self {
        StdScheduledMutator {
            name: Cow::from(format!(
                "StdScheduledMutator[{}]",
                mutations.names().join(", ")
            )),
            mutations,
            max_stack_pow,
            phantom: PhantomData,
        }
    }
}

/// Tuple type of the mutations that compose the Havoc mutator without crossover mutations
pub type HavocMutationsNoCrossoverType = tuple_list_type!(
    BitFlipMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteDecMutator,
    ByteNegMutator,
    ByteRandMutator,
    ByteAddMutator,
    WordAddMutator,
    DwordAddMutator,
    QwordAddMutator,
    ByteInterestingMutator,
    WordInterestingMutator,
    DwordInterestingMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesExpandMutator,
    BytesInsertMutator,
    BytesRandInsertMutator,
    BytesSetMutator,
    BytesRandSetMutator,
    BytesCopyMutator,
    BytesInsertCopyMutator,
    BytesSwapMutator,
);

/// Tuple type of the mutations that compose the Havoc mutator's crossover mutations
pub type HavocCrossoverType<I> =
    tuple_list_type!(CrossoverInsertMutator<I>, CrossoverReplaceMutator<I>);

/// Tuple type of the mutations that compose the Havoc mutator
pub type HavocMutationsType<I> = tuple_list_type!(
    BitFlipMutator,
    ByteFlipMutator,
    ByteIncMutator,
    ByteDecMutator,
    ByteNegMutator,
    ByteRandMutator,
    ByteAddMutator,
    WordAddMutator,
    DwordAddMutator,
    QwordAddMutator,
    ByteInterestingMutator,
    WordInterestingMutator,
    DwordInterestingMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesDeleteMutator,
    BytesExpandMutator,
    BytesInsertMutator,
    BytesRandInsertMutator,
    BytesSetMutator,
    BytesRandSetMutator,
    BytesCopyMutator,
    BytesInsertCopyMutator,
    BytesSwapMutator,
    CrossoverInsertMutator<I>,
    CrossoverReplaceMutator<I>,
);

/// Get the mutations that compose the Havoc mutator (only applied to single inputs)
#[must_use]
pub fn havoc_mutations_no_crossover() -> HavocMutationsNoCrossoverType {
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
    )
}

/// Get the mutations that compose the Havoc mutator's crossover strategy
#[must_use]
pub fn havoc_crossover<I>() -> HavocCrossoverType<I> {
    tuple_list!(
        CrossoverInsertMutator::new(),
        CrossoverReplaceMutator::new(),
    )
}

/// Get the mutations that compose the Havoc mutator
#[must_use]
pub fn havoc_mutations<I>() -> HavocMutationsType<I> {
    havoc_mutations_no_crossover().merge(havoc_crossover())
}

/// Get the mutations that uses the Tokens metadata
#[must_use]
pub fn tokens_mutations() -> tuple_list_type!(TokenInsert, TokenReplace) {
    tuple_list!(TokenInsert::new(), TokenReplace::new())
}

/// A logging [`Mutator`] that wraps around a [`StdScheduledMutator`].
pub struct LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, MT, S>,
{
    name: Cow<'static, str>,
    scheduled: SM,
    mutation_log: Vec<MutationId>,
    phantom: PhantomData<(I, MT, S)>,
}

impl<I, MT, S, SM> Debug for LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, MT, S>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LoggerScheduledMutator with {} mutations for Input type {}",
            MT::LEN,
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, S, SM> Named for LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, MT, S>,
{
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, MT, S, SM> Mutator<I, S> for LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, MT, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }

    fn post_exec(&mut self, state: &mut S, corpus_id: Option<CorpusId>) -> Result<(), Error> {
        if let Some(id) = corpus_id {
            let mut testcase = (*state.corpus_mut().get(id)?).borrow_mut();
            let mut log = Vec::<Cow<'static, str>>::new();
            while let Some(idx) = self.mutation_log.pop() {
                let name = self.scheduled.mutations().name(idx.0).unwrap().clone(); // TODO maybe return an Error on None
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

impl<I, MT, S, SM> ComposedByMutations<I, MT, S> for LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
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

impl<I, MT, S, SM> ScheduledMutator<I, MT, S> for LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, MT, S>,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(6))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(MT::LEN != 0);
        state.rand_mut().below(MT::LEN).into()
    }

    fn scheduled_mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let num = self.iterations(state, input);
        self.mutation_log.clear();
        for _ in 0..num {
            let idx = self.schedule(state, input);
            self.mutation_log.push(idx);
            let outcome = self.mutations_mut().get_and_mutate(idx, state, input)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
        }
        Ok(r)
    }
}

impl<I, MT, S, SM> LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, MT, S>,
{
    /// Create a new [`LoggerScheduledMutator`] instance without mutations and corpus
    /// This mutator logs all mutators.
    pub fn new(scheduled: SM) -> Self {
        Self {
            name: Cow::from(format!("LoggerScheduledMutator[{}]", scheduled.name())),
            scheduled,
            mutation_log: vec![],
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use libafl_bolts::rands::{StdRand, XkcdRand};

    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        feedbacks::ConstFeedback,
        inputs::{BytesInput, HasMutatorBytes},
        mutators::{
            mutations::SpliceMutator,
            scheduled::{havoc_mutations, StdScheduledMutator},
            Mutator,
        },
        state::StdState,
    };

    #[test]
    fn test_mut_scheduled() {
        let rand = XkcdRand::with_seed(0);
        let mut corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
        corpus
            .add(Testcase::new(vec![b'a', b'b', b'c'].into()))
            .unwrap();
        corpus
            .add(Testcase::new(vec![b'd', b'e', b'f'].into()))
            .unwrap();

        let mut input = corpus.cloned_input_for_id(corpus.first().unwrap()).unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut splice = SpliceMutator::new();
        splice.mutate(&mut state, &mut input).unwrap();

        log::trace!("{:?}", input.bytes());

        // The pre-seeded rand should have spliced at position 2.
        assert_eq!(input.bytes(), &[b'a', b'b', b'f']);
    }

    #[test]
    fn test_havoc() {
        let rand = StdRand::with_seed(0x1337);
        let mut corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
        corpus
            .add(Testcase::new(vec![b'a', b'b', b'c'].into()))
            .unwrap();
        corpus
            .add(Testcase::new(vec![b'd', b'e', b'f'].into()))
            .unwrap();

        let mut input = corpus.cloned_input_for_id(corpus.first().unwrap()).unwrap();
        let input_prior = input.clone();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut havoc = StdScheduledMutator::new(havoc_mutations());

        assert_eq!(input, input_prior);

        let mut equal_in_a_row = 0;

        for _ in 0..42 {
            havoc.mutate(&mut state, &mut input).unwrap();

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
