//! The `ScheduledMutator` schedules multiple mutations internally.

use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

use super::MutationId;
pub use crate::mutators::{mutations::*, token_mutations::*};
use crate::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, tuple_list_type, NamedTuple},
        AsMutSlice, AsSlice,
    },
    corpus::{Corpus, CorpusId},
    mutators::{MutationResult, Mutator, MutatorsTuple},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};

/// The metadata placed in a [`crate::corpus::Testcase`] by a [`LoggerScheduledMutator`].
#[derive(Debug, Serialize, Deserialize)]
pub struct LogMutationMetadata {
    /// A list of logs
    pub list: Vec<String>,
}

crate::impl_serdeany!(LogMutationMetadata);

impl AsSlice for LogMutationMetadata {
    type Entry = String;
    #[must_use]
    fn as_slice(&self) -> &[String] {
        self.list.as_slice()
    }
}
impl AsMutSlice for LogMutationMetadata {
    type Entry = String;
    #[must_use]
    fn as_mut_slice(&mut self) -> &mut [String] {
        self.list.as_mut_slice()
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
pub struct StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
{
    mutations: MT,
    max_stack_pow: u64,
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

impl<I, MT, S> Mutator<I, S> for StdScheduledMutator<I, MT, S>
where
    MT: MutatorsTuple<I, S>,
    S: HasRand,
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
        debug_assert!(!self.mutations().is_empty());
        state.rand_mut().below(self.mutations().len() as u64).into()
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
            mutations,
            max_stack_pow: 7,
            phantom: PhantomData,
        }
    }

    /// Create a new [`StdScheduledMutator`] instance specifying mutations and the maximun number of iterations
    pub fn with_max_stack_pow(mutations: MT, max_stack_pow: u64) -> Self {
        StdScheduledMutator {
            mutations,
            max_stack_pow,
            phantom: PhantomData,
        }
    }
}

/// Tuple type of the mutations that compose the Havoc mutator
pub type HavocMutationsType = tuple_list_type!(
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
    CrossoverInsertMutator,
    CrossoverReplaceMutator,
);

/// Get the mutations that compose the Havoc mutator
#[must_use]
pub fn havoc_mutations() -> HavocMutationsType {
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
pub fn tokens_mutations() -> tuple_list_type!(TokenInsert, TokenReplace) {
    tuple_list!(TokenInsert::new(), TokenReplace::new(),)
}

/// A logging [`Mutator`] that wraps around a [`StdScheduledMutator`].
pub struct LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
    SM: ScheduledMutator<I, MT, S>,
{
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
            self.scheduled.mutations().len(),
            core::any::type_name::<I>()
        )
    }
}

impl<I, MT, S, SM> Mutator<I, S> for LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
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
        corpus_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        if let Some(idx) = corpus_idx {
            let mut testcase = (*state.corpus_mut().get(idx)?).borrow_mut();
            let mut log = Vec::<String>::new();
            while let Some(idx) = self.mutation_log.pop() {
                let name = String::from(self.scheduled.mutations().name(idx.0).unwrap()); // TODO maybe return an Error on None
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
        debug_assert!(!self.scheduled.mutations().is_empty());
        state
            .rand_mut()
            .below(self.scheduled.mutations().len() as u64)
            .into()
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

impl<I, MT, S, SM> LoggerScheduledMutator<I, MT, S, SM>
where
    MT: MutatorsTuple<I, S> + NamedTuple,
    S: HasRand + HasCorpus,
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
        feedbacks::ConstFeedback,
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
        corpus
            .add(Testcase::new(vec![b'a', b'b', b'c'].into()))
            .unwrap();
        corpus
            .add(Testcase::new(vec![b'd', b'e', b'f'].into()))
            .unwrap();

        let testcase = corpus
            .get(corpus.first().unwrap())
            .expect("Corpus did not contain entries");
        let mut input = testcase.borrow_mut().load_input().unwrap().clone();

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
        corpus
            .add(Testcase::new(vec![b'a', b'b', b'c'].into()))
            .unwrap();
        corpus
            .add(Testcase::new(vec![b'd', b'e', b'f'].into()))
            .unwrap();

        let testcase = corpus
            .get(corpus.first().unwrap())
            .expect("Corpus did not contain entries");
        let mut input = testcase.borrow_mut().load_input().unwrap().clone();
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

/// `SchedulerMutator` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use pyo3::prelude::*;

    use super::{havoc_mutations, Debug, HavocMutationsType, StdScheduledMutator};
    use crate::{
        inputs::BytesInput, mutators::pybind::PythonMutator, state::pybind::PythonStdState,
    };

    #[pyclass(unsendable, name = "StdHavocMutator")]
    #[derive(Debug)]
    /// Python class for StdHavocMutator
    pub struct PythonStdHavocMutator {
        /// Rust wrapped StdHavocMutator object
        pub inner: StdScheduledMutator<BytesInput, HavocMutationsType, PythonStdState>,
    }

    #[pymethods]
    impl PythonStdHavocMutator {
        #[new]
        fn new() -> Self {
            Self {
                inner: StdScheduledMutator::new(havoc_mutations()),
            }
        }

        fn as_mutator(slf: Py<Self>) -> PythonMutator {
            PythonMutator::new_std_havoc(slf)
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonStdHavocMutator>()?;
        Ok(())
    }
}
