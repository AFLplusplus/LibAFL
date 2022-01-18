//! Corpuses contain the testcases, either in mem, on disk, or somewhere else.

pub mod testcase;
pub use testcase::{PowerScheduleTestcaseMetaData, Testcase};

pub mod inmemory;
pub use inmemory::InMemoryCorpus;

#[cfg(feature = "std")]
pub mod ondisk;
#[cfg(feature = "std")]
pub use ondisk::OnDiskCorpus;

#[cfg(feature = "std")]
pub mod cached;
#[cfg(feature = "std")]
pub use cached::CachedOnDiskCorpus;

pub mod queue;
pub use queue::QueueCorpusScheduler;

pub mod minimizer;
pub use minimizer::{
    FavFactor, IndexesLenTimeMinimizerCorpusScheduler, IsFavoredMetadata,
    LenTimeMinimizerCorpusScheduler, LenTimeMulFavFactor, MinimizerCorpusScheduler,
    TopRatedsMetadata,
};

pub mod powersched;
pub use powersched::PowerQueueCorpusScheduler;

use alloc::borrow::ToOwned;
use core::{cell::RefCell, marker::PhantomData};

use crate::{
    bolts::rands::Rand,
    inputs::Input,
    state::{HasCorpus, HasRand},
    Error,
};

/// Corpus with all current testcases
pub trait Corpus: serde::Serialize + serde::de::DeserializeOwned {
    type Input: Input;

    /// Returns the number of elements
    fn count(&self) -> usize;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Add an entry to the corpus and return its index
    fn add(&mut self, testcase: Testcase<Self::Input>) -> Result<usize, Error>;

    /// Replaces the testcase at the given idx
    fn replace(&mut self, idx: usize, testcase: Testcase<Self::Input>) -> Result<(), Error>;

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<Self::Input>>, Error>;

    /// Get by id
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<Self::Input>>, Error>;

    /// Current testcase scheduled
    fn current(&self) -> &Option<usize>;

    /// Current testcase scheduled (mut)
    fn current_mut(&mut self) -> &mut Option<usize>;
}

/// The scheduler define how the fuzzer requests a testcase from the corpus.
/// It has hooks to corpus add/replace/remove to allow complex scheduling algorithms to collect data.
pub trait CorpusScheduler {
    type State: HasCorpus;

    /// Add an entry to the corpus and return its index
    fn on_add(&self, _state: &mut Self::State, _idx: usize) -> Result<(), Error> {
        Ok(())
    }

    /// Replaces the testcase at the given idx
    fn on_replace(
        &self,
        _state: &mut Self::State,
        _idx: usize,
        _testcase: &Testcase<
            <<<Self as CorpusScheduler>::State as HasCorpus>::Corpus as Corpus>::Input,
        >,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn on_remove(
        &self,
        _state: &mut Self::State,
        _idx: usize,
        _testcase: &Option<
            Testcase<<<<Self as CorpusScheduler>::State as HasCorpus>::Corpus as Corpus>::Input>,
        >,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Gets the next entry
    fn next(&self, state: &mut Self::State) -> Result<usize, Error>;
}

/// Feed the fuzzer simpply with a random testcase on request
#[derive(Debug, Clone)]
pub struct RandCorpusScheduler<S>
where
    S: HasCorpus + HasRand,
{
    phantom: PhantomData<S>,
}

impl<S> CorpusScheduler for RandCorpusScheduler<S>
where
    S: HasCorpus + HasRand,
{
    type State = S;

    /// Gets the next entry at random
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty("No entries in corpus".to_owned()))
        } else {
            let len = state.corpus().count();
            let id = state.rand_mut().below(len as u64) as usize;
            *state.corpus_mut().current_mut() = Some(id);
            Ok(id)
        }
    }
}

impl<S> RandCorpusScheduler<S>
where
    S: HasCorpus + HasRand,
{
    /// Create a new [`RandCorpusScheduler`] that just schedules randomly.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<S> Default for RandCorpusScheduler<S>
where
    S: HasCorpus + HasRand,
{
    fn default() -> Self {
        Self::new()
    }
}

/// A [`StdCorpusScheduler`] uses the default scheduler in `LibAFL` to schedule [`Testcase`]s
/// The current `Std` is a [`RandCorpusScheduler`], although this may change in the future, if another [`CorpusScheduler`] delivers better results.
pub type StdCorpusScheduler<S> = RandCorpusScheduler<S>;
