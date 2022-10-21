//! The `ScheduledMutator` schedules multiple mutations internally.

use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Debug},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

pub use crate::mutators::{mutations::*, token_mutations::*};
use crate::{
    bolts::{
        rands::Rand,
        tuples::{tuple_list, tuple_list_type, NamedTuple},
        AsMutSlice, AsSlice,
    },
    corpus::Corpus,
    inputs::UsesInput,
    mutators::{MutationResult, Mutator, MutatorsTuple},
    state::{HasCorpus, HasMetadata, HasRand, State},
    Error,
};

/// The metadata placed in a [`crate::corpus::Testcase`] by a [`LoggerScheduledMutator`].
#[derive(Debug, Serialize, Deserialize)]
pub struct LogMutationMetadata {
    /// A list of logs
    pub list: Vec<String>,
}

crate::impl_serdeany!(LogMutationMetadata);

impl AsSlice<String> for LogMutationMetadata {
    #[must_use]
    fn as_slice(&self) -> &[String] {
        self.list.as_slice()
    }
}
impl AsMutSlice<String> for LogMutationMetadata {
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
pub trait ComposedByMutations<MT, S>
where
    MT: MutatorsTuple<S>,
    S: UsesInput,
{
    /// Get the mutations
    fn mutations(&self) -> &MT;

    /// Get the mutations (mutable)
    fn mutations_mut(&mut self) -> &mut MT;
}

/// A [`Mutator`] scheduling multiple [`Mutator`]s for an input.
pub trait ScheduledMutator<MT, S>: ComposedByMutations<MT, S> + Mutator<S>
where
    MT: MutatorsTuple<S>,
    S: UsesInput,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, input: &S::Input) -> u64;

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, input: &S::Input) -> usize;

    /// New default implementation for mutate.
    /// Implementations must forward mutate() to this method
    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
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
pub struct StdScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
{
    mutations: MT,
    max_stack_pow: u64,
    phantom: PhantomData<S>,
}

impl<MT, S> Debug for StdScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StdScheduledMutator with {} mutations for Input type {}",
            self.mutations.len(),
            core::any::type_name::<S::Input>()
        )
    }
}

impl<MT, S> Mutator<S> for StdScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
{
    #[inline]
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut S::Input,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        self.scheduled_mutate(state, input, stage_idx)
    }
}

impl<MT, S> ComposedByMutations<MT, S> for StdScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
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

impl<MT, S> ScheduledMutator<MT, S> for StdScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &S::Input) -> u64 {
        1 << (1 + state.rand_mut().below(self.max_stack_pow))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &S::Input) -> usize {
        debug_assert!(!self.mutations().is_empty());
        state.rand_mut().below(self.mutations().len() as u64) as usize
    }
}

impl<MT, S> StdScheduledMutator<MT, S>
where
    MT: MutatorsTuple<S>,
    S: State + HasRand,
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
pub struct LoggerScheduledMutator<MT, S, SM>
where
    MT: MutatorsTuple<S> + NamedTuple,
    S: UsesInput + HasRand + HasCorpus,
    SM: ScheduledMutator<MT, S>,
{
    scheduled: SM,
    mutation_log: Vec<usize>,
    phantom: PhantomData<(MT, S)>,
}

impl<MT, S, SM> Debug for LoggerScheduledMutator<MT, S, SM>
where
    MT: MutatorsTuple<S> + NamedTuple,
    S: UsesInput + HasRand + HasCorpus,
    SM: ScheduledMutator<MT, S>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LoggerScheduledMutator with {} mutations for Input type {}",
            self.scheduled.mutations().len(),
            core::any::type_name::<<S as UsesInput>::Input>()
        )
    }
}

impl<MT, S, SM> Mutator<S> for LoggerScheduledMutator<MT, S, SM>
where
    MT: MutatorsTuple<S> + NamedTuple,
    S: State + HasRand + HasCorpus,
    SM: ScheduledMutator<MT, S>,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut <S as UsesInput>::Input,
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

impl<MT, S, SM> ComposedByMutations<MT, S> for LoggerScheduledMutator<MT, S, SM>
where
    MT: MutatorsTuple<S> + NamedTuple,
    S: State + HasRand + HasCorpus,
    SM: ScheduledMutator<MT, S>,
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

impl<MT, S, SM> ScheduledMutator<MT, S> for LoggerScheduledMutator<MT, S, SM>
where
    MT: MutatorsTuple<S> + NamedTuple,
    S: State + HasRand + HasCorpus,
    SM: ScheduledMutator<MT, S>,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &<S as UsesInput>::Input) -> u64 {
        1 << (1 + state.rand_mut().below(6))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &<S as UsesInput>::Input) -> usize {
        debug_assert!(!self.scheduled.mutations().is_empty());
        state
            .rand_mut()
            .below(self.scheduled.mutations().len() as u64) as usize
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut <S as UsesInput>::Input,
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

impl<MT, S, SM> LoggerScheduledMutator<MT, S, SM>
where
    MT: MutatorsTuple<S> + NamedTuple,
    S: State + HasRand + HasCorpus,
    SM: ScheduledMutator<MT, S>,
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

        let testcase = corpus.get(0).expect("Corpus did not contain entries");
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

        let testcase = corpus.get(0).expect("Corpus did not contain entries");
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
    use crate::{mutators::pybind::PythonMutator, state::pybind::PythonStdState};

    #[pyclass(unsendable, name = "StdHavocMutator")]
    #[derive(Debug)]
    /// Python class for StdHavocMutator
    pub struct PythonStdHavocMutator {
        /// Rust wrapped StdHavocMutator object
        pub inner: StdScheduledMutator<HavocMutationsType, PythonStdState>,
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
