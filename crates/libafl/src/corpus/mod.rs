//! Corpuses contain the testcases, either in memory, on disk, or somewhere else.

use alloc::rc::Rc;
use core::{fmt, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::Error;

pub mod testcase;
pub use testcase::{
    HasTestcase, IsTestcaseMetadataCell, SchedulerTestcaseMetadata, Testcase,
    TestcaseFilenameFormat, TestcaseMetadata,
};

pub mod cache;
pub use cache::{Cache, FifoCache, IdentityCache};

pub mod single;
pub use single::SingleCorpus;

// pub mod dynamic;
// pub use dynamic::DynamicCorpus;

pub mod combined;
pub use combined::CombinedCorpus;

#[cfg(all(feature = "cmin", unix))]
pub mod minimizer;
#[cfg(all(feature = "cmin", unix))]
pub use minimizer::*;

pub mod nop;
pub use nop::NopCorpus;

pub mod store;
pub use store::{InMemoryStore, OnDiskStore, Store, maps};

pub mod collection;
pub use collection::{
    CachedOnDiskCorpus, InMemoryCorpus, InMemoryOnDiskCorpus, OnDiskCorpus, StdInMemoryCorpusMap,
    StdInMemoryStore, StdOnDiskStore,
};

/// An abstraction for the index that identify a testcase in the corpus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CorpusId(pub usize);

/// A counter for [`Corpus`] implementors.
/// Useful to generate fresh [`CorpusId`]s.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct CorpusCounter {
    /// A fresh, progressive ID
    /// It stores the next available ID.
    current_id: usize,
}

/// [`Iterator`] over the ids of a [`Corpus`]
#[derive(Debug)]
pub struct CorpusIdIterator<'a, C, I> {
    corpus: &'a C,
    cur: Option<CorpusId>,
    cur_back: Option<CorpusId>,
    phantom: PhantomData<I>,
}

/// Utility macro to call `Corpus::random_id`; fetches only enabled [`Testcase`]`s`
#[macro_export]
macro_rules! random_corpus_id {
    ($corpus:expr, $rand:expr) => {{
        let cnt = $corpus.count();
        #[cfg(debug_assertions)]
        let nth = $rand.below(core::num::NonZero::new(cnt).expect("Corpus may not be empty!"));
        // # Safety
        // This is a hot path. We try to be as fast as possible here.
        // In debug this is checked (see above.)
        // The worst that can happen is a wrong integer to get returned.
        // In this case, the call below will fail.
        #[cfg(not(debug_assertions))]
        let nth = $rand.below(unsafe { core::num::NonZero::new(cnt).unwrap_unchecked() });
        $corpus.nth(nth)
    }};
}

/// Utility macro to call `Corpus::random_id`; fetches both enabled and disabled [`Testcase`]`s`
/// Note: use `Corpus::get_from_all` as disabled entries are inaccessible from `Corpus::get`
#[macro_export]
macro_rules! random_corpus_id_with_disabled {
    ($corpus:expr, $rand:expr) => {{
        let cnt = $corpus.count_all();
        #[cfg(debug_assertions)]
        let nth = $rand.below(core::num::NonZero::new(cnt).expect("Corpus may not be empty!"));
        // # Safety
        // This is a hot path. We try to be as fast as possible here.
        // In debug this is checked (see above.)
        // The worst that can happen is a wrong integer to get returned.
        // In this case, the call below will fail.
        #[cfg(not(debug_assertions))]
        let nth = $rand.below(unsafe { core::num::NonZero::new(cnt).unwrap_unchecked() });
        $corpus.nth_from_all(nth)
    }};
}

/// Corpus with all current [`Testcase`]s, or solutions
pub trait Corpus<I>: Sized {
    /// A [`TestcaseMetadata`] cell.
    type TestcaseMetadataCell: IsTestcaseMetadataCell;

    /// Returns the number of all enabled entries
    fn count(&self) -> usize;

    /// Returns the number of all disabled entries
    fn count_disabled(&self) -> usize;

    /// Returns the number of elements including disabled entries
    fn count_all(&self) -> usize;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Add an enabled testcase to the corpus and return its index
    ///
    /// The default [`TestcaseMetadata`] will be instantiated.
    fn add(&mut self, input: I) -> Result<CorpusId, Error> {
        self.add_shared::<true>(Rc::new(input), TestcaseMetadata::default())
    }

    /// Add an enabled testcase to the corpus and return its index
    fn add_with_metadata(&mut self, input: I, md: TestcaseMetadata) -> Result<CorpusId, Error> {
        self.add_shared::<true>(Rc::new(input), md)
    }

    /// Add a disabled testcase to the corpus and return its index
    ///
    /// The default [`TestcaseMetadata`] will be instantiated.
    fn add_disabled(&mut self, input: I) -> Result<CorpusId, Error> {
        self.add_shared::<false>(Rc::new(input), TestcaseMetadata::default())
    }

    /// Add a disabled testcase to the corpus and return its index
    fn add_disabled_with_metadata(
        &mut self,
        input: I,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error> {
        self.add_shared::<false>(Rc::new(input), md)
    }

    /// Add a testcase to the corpus, and returns its index.
    /// The associated type tells whether the input should be added to the enabled or the disabled corpus.
    ///
    /// The input can be shared through [`Rc`].
    fn add_shared<const ENABLED: bool>(
        &mut self,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error>;

    /// Get testcase by id; considers only enabled testcases
    fn get(&self, id: CorpusId) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        Self::get_from::<true>(self, id)
    }

    /// Get testcase by id, looking at the enabled and disabled stores.
    fn get_from_all(&self, id: CorpusId) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        Self::get_from::<false>(self, id)
    }

    /// Get testcase by id
    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error>;

    /// Disable a corpus entry
    fn disable(&mut self, id: CorpusId) -> Result<(), Error>;

    /// Replace a [`TestcaseMetadata`] by another one.
    fn replace_metadata(
        &mut self,
        id: CorpusId,
        md: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error>;

    /// Current testcase scheduled
    fn current(&self) -> &Option<CorpusId>;

    /// Current testcase scheduled (mutable)
    fn current_mut(&mut self) -> &mut Option<CorpusId>;

    /// Get the next corpus id
    fn next(&self, id: CorpusId) -> Option<CorpusId>;

    /// Get the prev corpus id
    fn prev(&self, id: CorpusId) -> Option<CorpusId>;

    /// Get the first inserted corpus id
    fn first(&self) -> Option<CorpusId>;

    /// Get the last inserted corpus id
    fn last(&self) -> Option<CorpusId>;

    /// An iterator over very active corpus id
    fn ids(&self) -> CorpusIdIterator<'_, Self, I> {
        CorpusIdIterator {
            corpus: self,
            cur: self.first(),
            cur_back: self.last(),
            phantom: PhantomData,
        }
    }

    /// Get the nth corpus id; considers only enabled testcases
    fn nth(&self, nth: usize) -> CorpusId {
        self.ids()
            .nth(nth)
            .unwrap_or_else(|| panic!("Failed to get the {nth} CorpusId"))
    }

    /// Get the nth corpus id; considers both enabled and disabled testcases
    fn nth_from_all(&self, nth: usize) -> CorpusId;
}

/// Marker trait for corpus implementations that actually support enable/disable functionality
pub trait EnableDisableCorpus {
    /// Disables a testcase, moving it to the disabled map
    fn disable(&mut self, id: CorpusId) -> Result<(), Error>;

    /// Enables a testcase, moving it to the enabled map
    fn enable(&mut self, id: CorpusId) -> Result<(), Error>;
}

/// Trait for types which track the current corpus index
pub trait HasCurrentCorpusId {
    /// Set the current corpus index; we have started processing this corpus entry
    fn set_corpus_id(&mut self, id: CorpusId) -> Result<(), Error>;

    /// Clear the current corpus index; we are done with this entry
    fn clear_corpus_id(&mut self) -> Result<(), Error>;

    /// Fetch the current corpus index -- typically used after a state recovery or transfer
    fn current_corpus_id(&self) -> Result<Option<CorpusId>, Error>;
}

impl fmt::Display for CorpusId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<usize> for CorpusId {
    fn from(id: usize) -> Self {
        Self(id)
    }
}

impl From<u64> for CorpusId {
    fn from(id: u64) -> Self {
        Self(id as usize)
    }
}

impl From<CorpusId> for usize {
    /// Not that the `CorpusId` is not necessarily stable in the corpus (if we remove [`Testcase`]s, for example).
    fn from(id: CorpusId) -> Self {
        id.0
    }
}

impl<C, I> Iterator for CorpusIdIterator<'_, C, I>
where
    C: Corpus<I>,
{
    type Item = CorpusId;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(cur) = self.cur {
            self.cur = self.corpus.next(cur);
            Some(cur)
        } else {
            None
        }
    }
}

impl<C, I> DoubleEndedIterator for CorpusIdIterator<'_, C, I>
where
    C: Corpus<I>,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if let Some(cur_back) = self.cur_back {
            self.cur_back = self.corpus.prev(cur_back);
            Some(cur_back)
        } else {
            None
        }
    }
}

impl CorpusCounter {
    fn new_id(&mut self) -> CorpusId {
        let old = self.current_id;
        self.current_id += 1;
        CorpusId(old)
    }
}
