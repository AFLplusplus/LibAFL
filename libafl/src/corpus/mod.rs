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
pub trait Corpus<I>: serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
{
    /// Returns the number of elements
    fn count(&self) -> usize;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Add an entry to the corpus and return its index
    fn add(&mut self, testcase: Testcase<I>) -> Result<usize, Error>;

    /// Replaces the testcase at the given idx
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), Error>;

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error>;

    /// Get by id
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error>;

    /// Current testcase scheduled
    fn current(&self) -> &Option<usize>;

    /// Current testcase scheduled (mut)
    fn current_mut(&mut self) -> &mut Option<usize>;
}

/// The scheduler define how the fuzzer requests a testcase from the corpus.
/// It has hooks to corpus add/replace/remove to allow complex scheduling algorithms to collect data.
pub trait CorpusScheduler<I, S>
where
    I: Input,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, _state: &mut S, _idx: usize) -> Result<(), Error> {
        Ok(())
    }

    /// Replaces the testcase at the given idx
    fn on_replace(
        &self,
        _state: &mut S,
        _idx: usize,
        _testcase: &Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn on_remove(
        &self,
        _state: &mut S,
        _idx: usize,
        _testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Gets the next entry
    fn next(&self, state: &mut S) -> Result<usize, Error>;
}

/// Feed the fuzzer simpply with a random testcase on request
#[derive(Debug, Clone)]
pub struct RandCorpusScheduler<C, I, R, S>
where
    S: HasCorpus<C, I> + HasRand<R>,
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    phantom: PhantomData<(C, I, R, S)>,
}

impl<C, I, R, S> CorpusScheduler<I, S> for RandCorpusScheduler<C, I, R, S>
where
    S: HasCorpus<C, I> + HasRand<R>,
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
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

impl<C, I, R, S> RandCorpusScheduler<C, I, R, S>
where
    S: HasCorpus<C, I> + HasRand<R>,
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    /// Create a new [`RandCorpusScheduler`] that just schedules randomly.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<C, I, R, S> Default for RandCorpusScheduler<C, I, R, S>
where
    S: HasCorpus<C, I> + HasRand<R>,
    C: Corpus<I>,
    I: Input,
    R: Rand,
{
    fn default() -> Self {
        Self::new()
    }
}

/// A [`StdCorpusScheduler`] uses the default scheduler in `LibAFL` to schedule [`Testcase`]s
/// The current `Std` is a [`RandCorpusScheduler`], although this may change in the future, if another [`CorpusScheduler`] delivers better results.
pub type StdCorpusScheduler<C, I, R, S> = RandCorpusScheduler<C, I, R, S>;
