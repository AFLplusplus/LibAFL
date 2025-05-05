//! Stores are collections managing testcases

use core::cell::RefCell;
use std::rc::Rc;

use libafl_bolts::Error;

use super::{CorpusId, Testcase};

pub mod maps;
pub use maps::{BtreeCorpusMap, HashCorpusMap, InMemoryCorpusMap};

pub mod inmemory;
pub use inmemory::InMemoryStore;

pub mod ondisk;
pub use ondisk::OnDiskStore;

/// A store is responsible for storing and retrieving [`Testcase`]s, ordered by add time.
pub trait Store<I> {
    /// Returns the number of all enabled entries
    fn count(&self) -> usize;

    /// Returns the number of all disabled entries
    fn count_disabled(&self) -> usize;

    /// Returns the number of elements including disabled entries
    fn count_all(&self) -> usize {
        self.count().saturating_add(self.count_disabled())
    }

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Store the testcase associated to corpus_id to the enabled set.
    fn add(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<(), Error>;

    /// Store the testcase associated to corpus_id to the disabled set.
    fn add_disabled(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<(), Error>;

    /// Replaces the [`Testcase`] at the given idx in the enabled set, returning the existing.
    fn replace(&mut self, id: CorpusId, new_testcase: Testcase<I>) -> Result<Testcase<I>, Error>;

    /// Removes an entry from the corpus, returning it; considers both enabled and disabled testcases
    fn remove(&mut self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error>;

    /// Get by id; considers only enabled testcases
    fn get(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error>;

    /// Get by id; considers both enabled and disabled testcases
    fn get_from_all(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error>;

    /// Get the prev corpus id in chronological order
    fn prev(&self, id: CorpusId) -> Option<CorpusId>;

    /// Get the next corpus id in chronological order
    fn next(&self, id: CorpusId) -> Option<CorpusId>;

    /// Get the first inserted corpus id
    fn first(&self) -> Option<CorpusId>;

    /// Get the last inserted corpus id
    fn last(&self) -> Option<CorpusId>;

    /// Get the nth corpus id; considers only enabled testcases
    fn nth(&self, nth: usize) -> CorpusId;

    /// Get the nth corpus id; considers both enabled and disabled testcases
    fn nth_from_all(&self, nth: usize) -> CorpusId;
}
