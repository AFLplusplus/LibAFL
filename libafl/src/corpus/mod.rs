//! Corpuses contain the testcases, either in mem, on disk, or somewhere else.

pub mod testcase;
pub use testcase::Testcase;

use alloc::{vec::Vec};
use core::{cell::RefCell};

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
}

pub trait CorpusScheduler {

    /// Add an entry to the corpus and return its index
    fn on_add<C, I, R, S>(&self, state: &mut S, idx: usize, testcase: &Testcase<I>) -> Result<(), Error>
    where
        S: HasCorpus<C, I> + HasRand<R>,
        C: Corpus<I>,
        I: Input,
        R: Rand
    {
        Ok(())
    }

    /// Replaces the testcase at the given idx
    fn on_replace<C, I, R, S>(&self, state: &mut S, idx: usize, testcase: &Testcase<I>) -> Result<(), Error>
    where
        S: HasCorpus<C, I> + HasRand<R>,
        C: Corpus<I>,
        I: Input,
        R: Rand
    {
        Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn on_remove<C, I, R, S>(&self, state: &mut S, idx: usize, testcase: &Option<Testcase<I>>) -> Result<(), Error>
    where
        S: HasCorpus<C, I> + HasRand<R>,
        C: Corpus<I>,
        I: Input,
        R: Rand
    {
        Ok(())
    }

    // TODO: IntoIter
    /// Gets the next entry
    fn next<C, I, R, S>(&self, state: &mut S) -> Result<usize, Error>
    where
        S: HasCorpus<C, I> + HasRand<R>,
        C: Corpus<I>,
        I: Input,
        R: Rand;

}

pub struct RandCorpusScheduler {}

impl CorpusScheduler for RandCorpusScheduler {
    /// Gets the next entry at random
    fn next<C, I, R, S>(state: &mut S) -> Result<usize, Error>
    where
        S: HasCorpus<C, I> + HasRand<R>,
        C: Corpus<I>,
        I: Input,
        R: Rand
    {
        if state.corpus().count() == 0 {
            Err(Error::Empty("No entries in corpus".to_owned()))
        } else {
            let len = state.corpus().count();
            let id = state.rand_mut().below(len as u64) as usize;
            Ok(id)
        }
    }
}

pub struct InMemoryCorpus<I>
where
    I: Input,
{
    entries: Vec<RefCell<Testcase<I>>>,
}

impl<I, SC> Corpus<I> for InMemoryCorpus<I>
where
    I: Input,
{

    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.entries.len()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<usize, Error> {
        self.entries.push(RefCell::new(testcase));
        Ok(self.entries.len() - 1)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), Error> {
        if idx >= self.entries.len() {
            return Err(Error::KeyNotFound(format!("Index {} out of bounds", idx)));
        }
        self.entries[idx] = RefCell::new(testcase);
        Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error> {
        if idx >= self.entries.len() {
            Ok(None)
        } else {
            Ok(Some(self.entries.remove(idx).into_inner()))
        }
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error> {
        Ok(&self.entries[idx])
    }

    /*/// Add an entry to the corpus and return its index
    #[inline]
    fn add<R, S>(state: &mut S, testcase: Testcase<I>) -> Result<usize, Error>
    where
        S: HasCorpus<Self, I> + HasRand<R>,
        R: Rand
    {
        state.corpus_mut().entries.push(RefCell::new(testcase));
        let idx = state.corpus().entries.len() - 1;
        // Scheduler hook
        SC::on_add(state, idx, state.corpus().entries[idx].borrow())?;
        Ok(idx)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace<R, S>(state: &mut S, idx: usize, testcase: Testcase<I>) -> Result<(), Error>
    where
        S: HasCorpus<Self, I> + HasRand<R>,
        R: Rand
    {
        if state.corpus().entries.len() < idx {
            return Err(Error::KeyNotFound(format!("Index {} out of bounds", idx)));
        }
        state.corpus_mut().entries[idx] = RefCell::new(testcase);
        // Scheduler hook
        SC::on_replace(state, idx, state.corpus().entries[idx])?;
        Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove<R, S>(state: &mut S, idx: usize) -> Result<Option<Testcase<I>>, Error>
    where
        S: HasCorpus<Self, I> + HasRand<R>,
        R: Rand
    {
        let testcase = match state.corpus_mut()
            .entries
            .iter()
            .position(|x| ptr::eq(x.as_ptr(), entry))
        {
            Some(i) => Some(state.corpus_mut().entries.remove(i).into_inner()),
            None => None,
        };
        // Scheduler hook
        SC::on_remove(state, idx, &testcase)?;
        Ok(testcase)
    }*/
}
