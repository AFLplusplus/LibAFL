//! The `ScheduledMutator` schedules multiple mutations internally.

use alloc::{borrow::Cow, vec::Vec};
use core::{
    fmt::Debug,
    num::{NonZero, NonZeroUsize},
    ops::{Deref, DerefMut},
};

use libafl_bolts::{
    rands::Rand,
    tuples::{tuple_list, tuple_list_type, HasConstLen, NamedTuple},
    Named,
};
use serde::{Deserialize, Serialize};

use super::MutationId;
use crate::{
    corpus::{Corpus, CorpusId},
    mutators::{
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
pub trait ComposedByMutations {
    /// The mutations of this
    type Mutations;
    /// Get the mutations
    fn mutations(&self) -> &Self::Mutations;

    /// Get the mutations (mutable)
    fn mutations_mut(&mut self) -> &mut Self::Mutations;
}

/// A [`Mutator`] scheduling multiple [`Mutator`]s for an input.
pub trait ScheduledMutator<I, S>: ComposedByMutations + Mutator<I, S>
where
    Self::Mutations: MutatorsTuple<I, S>,
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
#[derive(Debug)]
pub struct StdScheduledMutator<MT> {
    name: Cow<'static, str>,
    mutations: MT,
    max_stack_pow: NonZeroUsize,
}

impl<MT> Named for StdScheduledMutator<MT> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, MT, S> Mutator<I, S> for StdScheduledMutator<MT>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    #[inline]
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input)
    }
}

impl<MT> ComposedByMutations for StdScheduledMutator<MT> {
    type Mutations = MT;
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

impl<I, MT, S> ScheduledMutator<I, S> for StdScheduledMutator<MT>
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
        debug_assert_ne!(self.mutations.len(), 0);
        // # Safety
        // We check for empty mutations
        state
            .rand_mut()
            .below(unsafe { NonZero::new(self.mutations.len()).unwrap_unchecked() })
            .into()
    }
}

impl<MT> StdScheduledMutator<MT>
where
    MT: NamedTuple,
{
    /// Create a new [`StdScheduledMutator`] instance specifying mutations
    pub fn new(mutations: MT) -> Self {
        StdScheduledMutator {
            name: Cow::from(format!(
                "StdScheduledMutator[{}]",
                mutations.names().join(", ")
            )),
            mutations,
            max_stack_pow: NonZero::new(7).unwrap(),
        }
    }

    /// Create a new [`StdScheduledMutator`] instance specifying mutations and the maximun number of iterations
    ///
    /// # Errors
    /// Will return [`Error::IllegalArgument`] for `max_stack_pow` of 0.
    #[inline]
    pub fn with_max_stack_pow(mutations: MT, max_stack_pow: usize) -> Result<Self, Error> {
        let Some(max_stack_pow) = NonZero::new(max_stack_pow) else {
            return Err(Error::illegal_argument("Max stack pow may not be 0."));
        };
        Ok(Self {
            name: Cow::from(format!(
                "StdScheduledMutator[{}]",
                mutations.names().join(", ")
            )),
            mutations,
            max_stack_pow,
        })
    }
}

/// Get the mutations that uses the Tokens metadata
#[must_use]
pub fn tokens_mutations() -> tuple_list_type!(TokenInsert, TokenReplace) {
    tuple_list!(TokenInsert::new(), TokenReplace::new())
}

/// A logging [`Mutator`] that wraps around a [`StdScheduledMutator`].
#[derive(Debug)]
pub struct LoggerScheduledMutator<SM> {
    name: Cow<'static, str>,
    scheduled: SM,
    mutation_log: Vec<MutationId>,
}

impl<SM> Named for LoggerScheduledMutator<SM> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S, SM> Mutator<I, S> for LoggerScheduledMutator<SM>
where
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, S>,
    SM::Mutations: MutatorsTuple<I, S> + NamedTuple,
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

impl<SM> ComposedByMutations for LoggerScheduledMutator<SM>
where
    SM: ComposedByMutations,
{
    type Mutations = SM::Mutations;
    #[inline]
    fn mutations(&self) -> &SM::Mutations {
        self.scheduled.mutations()
    }

    #[inline]
    fn mutations_mut(&mut self) -> &mut SM::Mutations {
        self.scheduled.mutations_mut()
    }
}

impl<I, S, SM> ScheduledMutator<I, S> for LoggerScheduledMutator<SM>
where
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, S>,
    SM::Mutations: MutatorsTuple<I, S> + NamedTuple,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &I) -> u64 {
        1 << (1 + state.rand_mut().below(NonZero::new(6).unwrap()))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &I) -> MutationId {
        debug_assert!(<SM::Mutations as HasConstLen>::LEN != 0);
        // # Safety
        // In debug we check the length. Worst case we end up with an illegal MutationId and fail later.
        state
            .rand_mut()
            .below(unsafe { NonZero::new(<SM::Mutations as HasConstLen>::LEN).unwrap_unchecked() })
            .into()
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

impl<SM> LoggerScheduledMutator<SM>
where
    SM: Named,
{
    /// Create a new [`LoggerScheduledMutator`] instance without mutations and corpus
    /// This mutator logs all mutators.
    pub fn new(scheduled: SM) -> Self {
        Self {
            name: Cow::from(format!("LoggerScheduledMutator[{}]", scheduled.name())),
            scheduled,
            mutation_log: vec![],
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
            havoc_mutations::havoc_mutations, mutations::SpliceMutator,
            scheduled::StdScheduledMutator, Mutator,
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
        assert_eq!(input.bytes(), b"abf");
    }

    #[test]
    fn test_havoc() {
        let rand = StdRand::with_seed(0x1337);
        let mut corpus: InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
        corpus.add(Testcase::new(b"abc".to_vec().into())).unwrap();
        corpus.add(Testcase::new(b"def".to_vec().into())).unwrap();

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
