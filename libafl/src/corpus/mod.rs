//! Corpuses contain the testcases, either in mem, on disk, or somewhere else.

pub mod testcase;
pub use testcase::Testcase;

pub mod inmemory;
pub use inmemory::InMemoryCorpus;

pub mod queue;
pub use queue::QueueCorpusScheduler;

use core::cell::RefCell;
use core::marker::PhantomData;

use crate::{
    inputs::Input,
    state::{HasCorpus, HasRand},
    utils::Rand,
    Error,
};

/// Corpus with all current testcases
pub trait Corpus<I>: serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
{
    /// Returns the number of elements
    fn count(&self) -> usize;

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

pub trait CorpusScheduler<I, S>
where
    I: Input,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, _state: &mut S, _idx: usize, _testcase: &Testcase<I>) -> Result<(), Error> {
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

    // TODO: IntoIter
    /// Gets the next entry
    fn next(&self, state: &mut S) -> Result<usize, Error>;
}

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

pub type StdCorpusScheduler<C, I, R, S> = RandCorpusScheduler<C, I, R, S>;
