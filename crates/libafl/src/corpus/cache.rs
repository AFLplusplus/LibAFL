//! A collection of cache policy implementations.
//! They are meant to be used by [`crate::corpus::CombinedCorpus`].
//!
//! Caches are acting on two [`Store`]s:
//!     - a **cache store** holding on the testcases with quick access.
//!     - a **backing store** with more expensive access, used when the testcase cannot be found in the cache store.

use alloc::rc::Rc;
use std::{cell::RefCell, collections::VecDeque, marker::PhantomData};

use libafl_bolts::Error;

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
#[derive(Debug)]
pub enum CachePolicy {
    /// Propagate the changes when the cell gets dropped.
    /// Expect more writes to the fallback store, with
    WritebackOnDrop,
    /// Propagate the changes when the cache is flushed explicitly.
    /// Less writes to the fallback stores will be issued, but the used is responsible for
    /// flushing the cache regularly, to avoid data loss.
    WritebackOnFlush,
}

/// Describe a cache policy
pub trait HasCachePolicy {
    /// The cache policy
    const CACHE_POLICY: CachePolicy;
}

/// An implementor for [`CachePolicy::WritebackOnDrop`]
#[derive(Debug)]
pub struct WritebackOnDropPolicy;
impl HasCachePolicy for WritebackOnDropPolicy {
    const CACHE_POLICY: CachePolicy = CachePolicy::WritebackOnDrop;
}

/// An implementor for [`CachePolicy::WritebackOnFlush`]
#[derive(Debug)]
pub struct WritebackOnFlushPolicy;
impl HasCachePolicy for WritebackOnFlushPolicy {
    const CACHE_POLICY: CachePolicy = CachePolicy::WritebackOnFlush;
}

/// A cache, managing a cache store and a fallback store.
pub trait Cache<CS, FS, I, P> {
    /// A [`TestcaseMetadata`] cell.
    type TestcaseMetadataCell: IsTestcaseMetadataCell;

    /// Add a testcase to the cache
    fn add(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error>;

    /// Add a disabled testcase to the cache
    fn add_disabled(
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
    fn written(&mut self, id: CorpusId);
}

/// A composed testcase metadata cell, linking the cached cell with the fallback cell.
#[derive(Debug, Clone)]
pub struct CacheTestcaseMetadataCell<CC, FC>
where
    CC: IsTestcaseMetadataCell,
    FC: IsTestcaseMetadataCell,
{
    write_access: RefCell<bool>,
    cache_cell: CC,
    fallback_cell: FC,
}

/// An identity cache, storing everything both in the cache and the backing store.
#[derive(Debug)]
pub struct IdentityCache<M> {
    cell_map: M,
}

/// A `First In / First Out` cache policy.
#[derive(Debug)]
pub struct FifoCache<CS, FS, I> {
    cached_ids: VecDeque<CorpusId>,
    cache_max_len: usize,
    phantom: PhantomData<(I, CS, FS)>,
}

impl<CC, FC> CacheTestcaseMetadataCell<CC, FC>
where
    CC: IsTestcaseMetadataCell,
    FC: IsTestcaseMetadataCell,
{
    /// Create a new [`CacheTestcaseMetadataCell`]
    pub fn new(cache_cell: CC, fallback_cell: FC) -> Self {
        Self {
            write_access: RefCell::new(false),
            cache_cell,
            fallback_cell,
        }
    }
}

impl<CC, FC> IsTestcaseMetadataCell for CacheTestcaseMetadataCell<CC, FC>
where
    CC: IsTestcaseMetadataCell,
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

    fn testcase_metadata<'a>(&'a self) -> Self::TestcaseMetadataRef<'a> {
        self.cache_cell.testcase_metadata()
    }

    fn testcase_metadata_mut<'a>(&'a self) -> Self::TestcaseMetadataRefMut<'a> {
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

impl<CC, FC> Drop for CacheTestcaseMetadataCell<CC, FC>
where
    CC: IsTestcaseMetadataCell,
    FC: IsTestcaseMetadataCell,
{
    fn drop(&mut self) {
        self.flush().unwrap();
    }
}

impl<CS, FS, I, M, P> Cache<CS, FS, I, P> for IdentityCache<M>
where
    CS: RemovableStore<I>,
    FS: Store<I>,
    I: Input,
    M: InMemoryCorpusMap<
        Testcase<
            I,
            Rc<CacheTestcaseMetadataCell<CS::TestcaseMetadataCell, FS::TestcaseMetadataCell>>,
        >,
    >,
    P: HasCachePolicy,
    <CS as Store<I>>::TestcaseMetadataCell: Clone,
    <FS as Store<I>>::TestcaseMetadataCell: Clone,
{
    type TestcaseMetadataCell =
        Rc<CacheTestcaseMetadataCell<CS::TestcaseMetadataCell, FS::TestcaseMetadataCell>>;

    fn add(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        cache_store.add(id, input.clone(), md.clone())?;
        fallback_store.add(id, input, md)
    }

    fn add_disabled(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        cache_store.add_disabled(id, input.clone(), md.clone())?;
        fallback_store.add_disabled(id, input, md)
    }

    fn get_from<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        if let Some(tc) = self.cell_map.get(id) {
            Ok(tc.clone())
        } else {
            let (input, cc) = cache_store.get_from::<ENABLED>(id)?.into_inner();
            let (_, fc) = fallback_store.get_from::<ENABLED>(id)?.into_inner();

            let cache_cell = Rc::new(CacheTestcaseMetadataCell::new(cc, fc));
            let testcase = Testcase::new(input, cache_cell.clone());

            self.cell_map.add(id, testcase.clone());

            Ok(testcase)
        }
    }

    // fn replace(
    //     &mut self,
    //     id: CorpusId,
    //     input: Rc<I>,
    //     md: TestcaseMetadata,
    //     cache_store: &mut CS,
    //     fallback_store: &mut FS,
    // ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
    //     let old_tc = cache_store.replace(id, input.clone(), md.clone())?;
    //     fallback_store.replace(id, input, md)?;

    //     Ok(old_tc)
    // }

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

    fn written(&mut self, _id: CorpusId) {
        todo!()
    }
}

impl<CS, FS, I> FifoCache<CS, FS, I>
where
    CS: RemovableStore<I>,
    FS: Store<I>,
    I: Clone,
{
    fn get_inner<CAF, CGF, CRF, FGF>(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
        cache_add_fn: CAF,
        cache_get_fn: CGF,
        cache_rm_fn: CRF,
        fallback_get_fn: FGF,
    ) -> Result<Testcase<I, CS::TestcaseMetadataCell>, Error>
    where
        CAF: FnOnce(&mut CS, CorpusId, Testcase<I, RefCell<TestcaseMetadata>>) -> Result<(), Error>,
        CGF: FnOnce(&CS, CorpusId) -> Result<Testcase<I, CS::TestcaseMetadataCell>, Error>,
        CRF: FnOnce(&mut CS, CorpusId) -> Result<Testcase<I, CS::TestcaseMetadataCell>, Error>,
        FGF: FnOnce(&FS, CorpusId) -> Result<Testcase<I, FS::TestcaseMetadataCell>, Error>,
    {
        if self.cached_ids.contains(&id) {
            cache_get_fn(cache_store, id)
        } else {
            if self.cached_ids.len() == self.cache_max_len {
                let to_evict = self.cached_ids.pop_back().unwrap();
                cache_rm_fn(cache_store, to_evict)?;
            }

            debug_assert!(self.cached_ids.len() < self.cache_max_len);

            // tescase is not cached, fetch it from fallback
            let fb_tc = fallback_get_fn(&fallback_store, id)?.cloned();
            cache_add_fn(cache_store, id, fb_tc)?;

            self.cached_ids.push_front(id);

            cache_get_fn(cache_store, id)
        }
    }
}

impl<CS, FS, I, P> Cache<CS, FS, I, P> for FifoCache<CS, FS, I>
where
    CS: RemovableStore<I>,
    FS: Store<I>,
    I: Clone,
{
    type TestcaseMetadataCell = CS::TestcaseMetadataCell;

    fn add(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        metadata: TestcaseMetadata,
        _cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        fallback_store.add(id, input, metadata)
    }

    fn add_disabled(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        metadata: TestcaseMetadata,
        _cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        fallback_store.add_disabled(id, input, metadata)
    }

    fn get_from<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.get_inner(
            id,
            cache_store,
            fallback_store,
            |cache_store, corpus_id, testcase| {
                let (input, md) = testcase.into_inner();
                cache_store.add(corpus_id, input, md.into_testcase_metadata())
            },
            |cache_store, corpus_id| cache_store.get(corpus_id),
            |cache_store, corpus_id| cache_store.remove(corpus_id),
            |fallback_store, corpus_id| fallback_store.get_from::<ENABLED>(corpus_id),
        )
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

    fn written(&mut self, _id: CorpusId) {
        todo!()
    }
}
