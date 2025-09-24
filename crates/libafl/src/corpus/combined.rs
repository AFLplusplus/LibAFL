//! A cached corpus, using a given [`Cache`] policy and two [`Store`]s.

use alloc::{rc::Rc, vec::Vec};
use core::{cell::RefCell, marker::PhantomData};

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use super::{Cache, Corpus, CorpusCounter, CorpusId, Testcase, store::Store};
use crate::corpus::testcase::TestcaseMetadata;

/// A [`CombinedCorpus`] tries first to use the main store according to some policy.
/// If it fails, it falls back to the secondary store.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CombinedCorpus<C, CS, FS, I> {
    /// The cache store
    cache_store: RefCell<CS>,
    /// The fallback store
    fallback_store: FS,
    /// The policy taking decisions
    cache: Rc<RefCell<C>>,
    /// The corpus ID counter
    counter: CorpusCounter,
    /// The keys in order (use `Vec::binary_search`)
    keys: Vec<CorpusId>,
    /// The current ID
    current: Option<CorpusId>,
    phantom: PhantomData<I>,
}

impl<C, CS, FS, I> CombinedCorpus<C, CS, FS, I> {
    /// Create a new [`CombinedCorpus`].
    pub fn new(cache: C, cache_store: CS, fallback_store: FS) -> Self {
        Self {
            cache: Rc::new(RefCell::new(cache)),
            cache_store: RefCell::new(cache_store),
            fallback_store,
            counter: CorpusCounter::default(),
            keys: Vec::new(),
            current: None,
            phantom: PhantomData,
        }
    }

    /// Get the fallback store reference
    pub fn fallback_store(&self) -> &FS {
        &self.fallback_store
    }
}

impl<C, CS, FS, I> Default for CombinedCorpus<C, CS, FS, I>
where
    C: Default,
    CS: Default,
    FS: Default,
{
    fn default() -> Self {
        Self::new(C::default(), CS::default(), FS::default())
    }
}

impl<C, CS, FS, I> Corpus<I> for CombinedCorpus<C, CS, FS, I>
where
    C: Cache<CS, FS, I>,
    CS: Store<I>,
    FS: Store<I>,
    I: Clone,
{
    type TestcaseMetadataCell = C::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.fallback_store.count()
    }

    fn count_disabled(&self) -> usize {
        self.fallback_store.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.fallback_store.count_all()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error> {
        let new_id = self.counter.new_id();

        self.cache.borrow_mut().add_shared::<ENABLED>(
            new_id,
            input,
            md,
            &mut *self.cache_store.borrow_mut(),
            &mut self.fallback_store,
        )?;

        Ok(new_id)
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        let mut cache = self.cache.borrow_mut();
        let cache_store = &mut *self.cache_store.borrow_mut();

        cache.get_from::<ENABLED>(id, cache_store, &self.fallback_store)
    }

    fn disable(&mut self, id: CorpusId) -> Result<(), Error> {
        self.cache.borrow_mut().disable(
            id,
            &mut *self.cache_store.borrow_mut(),
            &mut self.fallback_store,
        )
    }

    fn replace_metadata(
        &mut self,
        id: CorpusId,
        md: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        self.cache.borrow_mut().replace_metadata(
            id,
            md,
            &mut *self.cache_store.borrow_mut(),
            &mut self.fallback_store,
        )
    }

    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.fallback_store.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.fallback_store.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.fallback_store.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.fallback_store.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.fallback_store.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.fallback_store.nth_from_all(nth)
    }
}
