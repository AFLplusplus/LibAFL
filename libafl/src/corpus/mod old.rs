//! Corpuses contain the testcases, either in mem, on disk, or somewhere else.
//! They will hand out the next fuzz target, potentially doing basic scheduling.

pub mod testcase;
pub use testcase::Testcase;

pub mod inmemory;
pub use inmemory::InMemoryCorpus;

#[cfg(feature = "std")]
pub mod ondisk;
#[cfg(feature = "std")]
pub use ondisk::OnDiskCorpus;

pub mod queue;
pub use queue::QueueCorpus;

use alloc::{borrow::ToOwned, vec::Vec};
use core::{cell::RefCell, ptr};

use crate::{inputs::Input, utils::Rand, Error};

/// A way to obtain the containing testcase entries
pub trait HasTestcaseVec<I>
where
    I: Input,
{
    /// Get the entries vector field
    fn entries(&self) -> &[RefCell<Testcase<I>>];

    /// Get the entries vector field (mutable)
    fn entries_mut(&mut self) -> &mut Vec<RefCell<Testcase<I>>>;
}

/// Corpus with all current testcases
pub trait Corpus<I, R>: HasTestcaseVec<I> + serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
    R: Rand,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.entries().len()
    }
    
    // TODO implement a was_fuzzed counter

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> usize {
        self.entries_mut().push(RefCell::new(testcase));
        self.entries().len() - 1
    }

    /// Replaces the testcase at the given idx
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), Error> {
        if self.entries_mut().len() < idx {
            return Err(Error::KeyNotFound(format!("Index {} out of bounds", idx)));
        }
        self.entries_mut()[idx] = RefCell::new(testcase);
        Ok(())
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> &RefCell<Testcase<I>> {
        &self.entries()[idx]
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, entry: &Testcase<I>) -> Option<Testcase<I>> {
        match self
            .entries()
            .iter()
            .position(|x| ptr::eq(x.as_ptr(), entry))
        {
            Some(i) => Some(self.entries_mut().remove(i).into_inner()),
            None => None,
        }
    }

    /// Gets a random entry
    #[inline]
    fn random_entry(&self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), Error> {
        if self.count() == 0 {
            Err(Error::Empty("No entries in corpus".to_owned()))
        } else {
            let len = { self.entries().len() };
            let id = rand.below(len as u64) as usize;
            Ok((self.get(id), id))
        }
    }

    // TODO: IntoIter
    /// Gets the next entry
    fn next(&mut self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), Error>;

    /// Returns the testacase we currently use
    fn current_testcase(&self) -> (&RefCell<Testcase<I>>, usize);
}

