//! A collection of cache policy implementations.
//! They are meant to be used by [`crate::corpus::CombinedCorpus`].
//!
//! Caches are acting on two [`Store`]s:
//!     - a **cache store** holding on the testcases with quick access.
//!     - a **backing store** with more expensive access, used when the testcase cannot be found in the cache store.

use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use core::{cell::RefCell, marker::PhantomData};

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{
        CorpusId, Testcase,
        maps::InMemoryCorpusMap,
        store::{RemovableStore, Store},
        testcase::{IsTestcaseMetadataCell, TestcaseMetadata},
    },
    inputs::Input,
};

/// Describes how a change to metadata should be propagated to the fallback store
pub trait HasCachePolicy {
    /// Mark a corpus id as dirty
    fn dirty(&self, corpus_id: CorpusId);
}

/// Propagate the changes when the cell gets dropped.
/// Expect more writes to the fallback store.
#[derive(Debug, Serialize, Deserialize)]
pub struct WritebackOnDropPolicy;
impl HasCachePolicy for WritebackOnDropPolicy {
    fn dirty(&self, _corpus_id: CorpusId) {
        // do nothing
    }
}

/// Propagate the changes when the cache is flushed explicitly.
///
/// Less writes to the fallback stores will be issued, but the used is responsible for
/// flushing the cache regularly.
/// If the cache is not flushed, no data will be written to the fallback store, resulting in
/// data loss.
#[derive(Debug, Serialize, Deserialize)]
pub struct WritebackOnFlushPolicy {
    dirty_entries: RefCell<Vec<CorpusId>>,
}

impl HasCachePolicy for WritebackOnFlushPolicy {
    fn dirty(&self, corpus_id: CorpusId) {
        self.dirty_entries.borrow_mut().push(corpus_id);
    }
}

/// A cache, managing a cache store and a fallback store.
pub trait Cache<CS, FS, I> {
    /// A [`TestcaseMetadata`] cell.
    type TestcaseMetadataCell: IsTestcaseMetadataCell;

    /// Add a testcase to the cache
    fn add_shared<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error>;

    /// Get a testcase from the cache
    fn get_from<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error>;

    /// Disable an entry
    fn disable(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error>;

    /// Replace a testcase in the cache
    fn replace_metadata(
        &mut self,
        id: CorpusId,
        md: TestcaseMetadata,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Self::TestcaseMetadataCell, Error>;

    /// Flush the cache, committing the cached testcase to the fallback store.
    fn flush(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error>;

    /// Mark a corpus entry as written explicitly, for subsequent flushes.
    ///
    /// Thus, a cache [`Self::flush`] should propagate to entries marked as [`Self::written`].
    fn written(&self, id: CorpusId);
}

/// A composed testcase metadata cell, linking the cached cell with the fallback cell.
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheTestcaseMetadataCell<CC, CP, FC>
where
    CC: IsTestcaseMetadataCell,
    CP: HasCachePolicy,
    FC: IsTestcaseMetadataCell,
{
    write_access: RefCell<bool>,
    cache_policy: Rc<CP>,
    cache_cell: CC,
    fallback_cell: Rc<FC>,
}

impl<CC, CP, FC> Clone for CacheTestcaseMetadataCell<CC, CP, FC>
where
    CC: IsTestcaseMetadataCell + Clone,
    CP: HasCachePolicy,
    FC: IsTestcaseMetadataCell,
{
    fn clone(&self) -> Self {
        Self {
            write_access: self.write_access.clone(),
            cache_policy: self.cache_policy.clone(),
            cache_cell: self.cache_cell.clone(),
            fallback_cell: self.fallback_cell.clone(),
        }
    }
}

/// The standard cell for testcase metadata in an identity cache.
pub type StdIdentityCacheTestcaseMetadataCell<I, CS, FS> = Rc<
    CacheTestcaseMetadataCell<
        <CS as Store<I>>::TestcaseMetadataCell,
        WritebackOnFlushPolicy,
        <FS as Store<I>>::TestcaseMetadataCell,
    >,
>;

/// An identity cache, storing everything both in the cache and the backing store.
///
/// It only supports [`WritebackOnFlushPolicy`] since all the testcases are stored in memory on load
/// forever.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityCache<M> {
    #[serde(skip)]
    cell_map: RefCell<M>,
    cache_policy: Rc<WritebackOnFlushPolicy>,
}

/// A `First In / First Out` cache policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FifoCache<CS, FS, I> {
    cached_ids: VecDeque<CorpusId>,
    cache_max_len: usize,
    phantom: PhantomData<(I, CS, FS)>,
}

impl<CS, FS, I> FifoCache<CS, FS, I> {
    /// Create a new [`FifoCache`], with at most `cache_max_len` [`Testcase`]s loaded in memory.
    #[must_use]
    pub fn new(cache_max_len: usize) -> Self {
        Self {
            cached_ids: VecDeque::default(),
            cache_max_len,
            phantom: PhantomData,
        }
    }
}

impl<CC, CP, FC> CacheTestcaseMetadataCell<CC, CP, FC>
where
    CC: IsTestcaseMetadataCell,
    CP: HasCachePolicy,
    FC: IsTestcaseMetadataCell,
{
    /// Create a new [`CacheTestcaseMetadataCell`]
    pub fn new(cache_policy: Rc<CP>, cache_cell: CC, fallback_cell: FC) -> Self {
        Self {
            cache_policy,
            write_access: RefCell::new(false),
            cache_cell,
            fallback_cell: Rc::new(fallback_cell),
        }
    }
}

impl<CC, CP, FC> IsTestcaseMetadataCell for CacheTestcaseMetadataCell<CC, CP, FC>
where
    CC: IsTestcaseMetadataCell,
    CP: HasCachePolicy,
    FC: IsTestcaseMetadataCell,
{
    type TestcaseMetadataRef<'a>
        = CC::TestcaseMetadataRef<'a>
    where
        Self: 'a;
    type TestcaseMetadataRefMut<'a>
        = CC::TestcaseMetadataRefMut<'a>
    where
        Self: 'a;

    fn testcase_metadata(&self) -> Self::TestcaseMetadataRef<'_> {
        self.cache_cell.testcase_metadata()
    }

    fn testcase_metadata_mut(&self) -> Self::TestcaseMetadataRefMut<'_> {
        *self.write_access.borrow_mut() = true;
        self.cache_cell.testcase_metadata_mut()
    }

    fn into_testcase_metadata(self) -> TestcaseMetadata {
        self.cache_cell.testcase_metadata().clone()
    }

    fn replace_testcase_metadata(&self, testcase_metadata: TestcaseMetadata) -> TestcaseMetadata {
        self.fallback_cell
            .replace_testcase_metadata(testcase_metadata.clone());
        self.cache_cell.replace_testcase_metadata(testcase_metadata)
    }

    fn flush(&self) -> Result<(), Error> {
        let write_access = self.write_access.borrow_mut();

        if *write_access {
            *self.fallback_cell.testcase_metadata_mut() =
                self.cache_cell.testcase_metadata().clone();
            self.fallback_cell.flush()?;
            *self.write_access.borrow_mut() = false;
        }

        Ok(())
    }
}

impl<CC, CP, FC> Drop for CacheTestcaseMetadataCell<CC, CP, FC>
where
    CC: IsTestcaseMetadataCell,
    CP: HasCachePolicy,
    FC: IsTestcaseMetadataCell,
{
    fn drop(&mut self) {
        self.flush().unwrap();
    }
}

impl<CS, FS, I, M> Cache<CS, FS, I> for IdentityCache<M>
where
    CS: RemovableStore<I>,
    FS: Store<I>,
    I: Input,
    M: InMemoryCorpusMap<Testcase<I, StdIdentityCacheTestcaseMetadataCell<I, CS, FS>>>,
    <CS as Store<I>>::TestcaseMetadataCell: Clone,
{
    type TestcaseMetadataCell = StdIdentityCacheTestcaseMetadataCell<I, CS, FS>;

    fn add_shared<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        cache_store.add_shared::<ENABLED>(id, input.clone(), md.clone())?;
        fallback_store.add_shared::<ENABLED>(id, input, md)
    }

    fn get_from<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        if let Some(tc) = self.cell_map.borrow().get(id) {
            Ok(tc.clone())
        } else {
            let (input, cc) = cache_store.get_from::<ENABLED>(id)?.into_inner();
            let (_, fc) = fallback_store.get_from::<ENABLED>(id)?.into_inner();

            let cache_cell = Rc::new(CacheTestcaseMetadataCell::new(
                self.cache_policy.clone(),
                cc,
                fc,
            ));
            let testcase = Testcase::new(input, cache_cell.clone());

            self.cell_map.borrow_mut().add(id, testcase.clone());

            Ok(testcase)
        }
    }

    fn disable(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        cache_store.disable(id)?;
        fallback_store.disable(id)
    }

    fn replace_metadata(
        &mut self,
        _id: CorpusId,
        _md: TestcaseMetadata,
        _cache_store: &mut CS,
        _fallback_store: &mut FS,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        todo!()
    }

    fn flush(
        &mut self,
        _id: CorpusId,
        _cache_store: &mut CS,
        _fallback_store: &mut FS,
    ) -> Result<(), Error> {
        todo!()
    }

    fn written(&self, id: CorpusId) {
        self.cache_policy.dirty(id);
    }
}

impl<CS, FS, I> Cache<CS, FS, I> for FifoCache<CS, FS, I>
where
    CS: RemovableStore<I>,
    FS: Store<I>,
    I: Clone,
{
    type TestcaseMetadataCell = CS::TestcaseMetadataCell;

    fn add_shared<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        metadata: TestcaseMetadata,
        _cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        fallback_store.add_shared::<ENABLED>(id, input, metadata)
    }

    fn get_from<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        if self.cached_ids.contains(&id) {
            cache_store.get(id)
        } else {
            if self.cached_ids.len() == self.cache_max_len {
                let to_evict = self.cached_ids.pop_back().unwrap();
                cache_store.remove(to_evict)?;
            }

            debug_assert!(self.cached_ids.len() < self.cache_max_len);

            // tescase is not cached, fetch it from fallback
            let fb_tc = fallback_store.get_from::<ENABLED>(id)?.cloned();
            let (input, md) = fb_tc.into_inner();

            cache_store.add_shared::<ENABLED>(id, input, md.into_testcase_metadata())?;

            self.cached_ids.push_front(id);

            cache_store.get(id)
        }
    }

    fn disable(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        cache_store.disable(id)?;
        fallback_store.disable(id)
    }

    fn replace_metadata(
        &mut self,
        _id: CorpusId,
        _md: TestcaseMetadata,
        _cache_store: &mut CS,
        _fallback_store: &mut FS,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        todo!()
    }

    fn flush(
        &mut self,
        _id: CorpusId,
        _cache_store: &mut CS,
        _fallback_store: &mut FS,
    ) -> Result<(), Error> {
        todo!()
    }

    fn written(&self, _id: CorpusId) {
        todo!()
    }
}
