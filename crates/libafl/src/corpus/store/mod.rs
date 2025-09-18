//! Stores are collections managing testcases

use alloc::rc::Rc;

use libafl_bolts::Error;

use super::{CorpusId, Testcase};
use crate::corpus::testcase::{IsTestcaseMetadataCell, TestcaseMetadata};

pub mod maps;
pub use maps::{BtreeCorpusMap, HashCorpusMap, InMemoryCorpusMap};

pub mod inmemory;
pub use inmemory::InMemoryStore;

pub mod ondisk;
pub use ondisk::{OnDiskMetadataFormat, OnDiskStore};

/// A store is responsible for storing and retrieving [`Testcase`]s, ordered by add time.
pub trait Store<I> {
    /// A [`TestcaseMetadata`] cell.
    type TestcaseMetadataCell: IsTestcaseMetadataCell;

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

    /// Store the testcase associated to corpus_id to the set.
    fn add_shared<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<(), Error>;

    /// Get testcase by id; considers only enabled testcases
    fn get(&self, id: CorpusId) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        Self::get_from::<true>(self, id)
    }

    /// Get testcase by id; considers both enabled and disabled testcases
    fn get_from_all(&self, id: CorpusId) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        Self::get_from::<false>(self, id)
    }

    /// Get testcase by id
    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error>;

    /// Replaces the [`Testcase`] at the given idx in the enabled set, returning the existing.
    fn replace_metadata(
        &mut self,
        id: CorpusId,
        metadata: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error>;

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

/// A Store with removable entries
pub trait RemovableStore<I>: Store<I> {
    /// Removes an entry from the corpus, returning it; considers both enabled and disabled testcases
    fn remove(&mut self, id: CorpusId) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error>;
}
