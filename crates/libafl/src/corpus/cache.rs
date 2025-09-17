//! A collection of cache policy implementations.
//! They are meant to be used by [`crate::corpus::CombinedCorpus`].
//!
//! Caches are acting on two [`Store`]s:
//!     - a **cache store** holding on the testcases with quick access.
//!     - a **backing store** with more expensive access, used when the testcase cannot be found in the cache store.

use alloc::rc::Rc;
use std::{cell::RefCell, collections::VecDeque, marker::PhantomData};

use libafl_bolts::Error;

use crate::corpus::{
    CorpusId, Testcase,
    store::{RemovableStore, Store},
    testcase::{HasTestcaseMetadata, TestcaseMetadata},
};

/// A First In -> First Out cache policy.
#[derive(Debug)]
pub struct FifoCache<CS, FS, I> {
    cached_ids: VecDeque<CorpusId>,
    cache_max_len: usize,
    phantom: PhantomData<(I, CS, FS)>,
}

/// An identity cache, storing everything both in the cache and the backing store.
#[derive(Debug)]
pub struct IdentityCache;

/// A cache, managing a cache store and a fallback store.
pub trait Cache<CS, FS, I> {
    /// A [`TestcaseMetadata`] cell.
    type TestcaseMetadataCell: HasTestcaseMetadata;

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
    fn replace(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error>;

    /// Flush the cache, committing the cached testcase to the fallback store.
    fn flush(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error>;
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

impl<CS, FS, I> Cache<CS, FS, I> for IdentityCache
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
        _fallback_store: &FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        cache_store.get_from::<ENABLED>(id)
    }

    fn replace(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        let old_tc = cache_store.replace(id, input.clone(), md.clone())?;
        fallback_store.replace(id, input, md)?;

        Ok(old_tc)
    }

    fn flush(
        &mut self,
        _id: CorpusId,
        _cache_store: &mut CS,
        _fallback_store: &mut FS,
    ) -> Result<(), Error> {
        todo!()
    }
}

impl<CS, FS, I> Cache<CS, FS, I> for FifoCache<CS, FS, I>
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
                cache_store.add(corpus_id, input, md)
            },
            |cache_store, corpus_id| cache_store.get(corpus_id),
            |cache_store, corpus_id| cache_store.remove(corpus_id),
            |fallback_store, corpus_id| fallback_store.get_from::<ENABLED>(corpus_id),
        )
    }

    fn replace(
        &mut self,
        _id: CorpusId,
        _input: Rc<I>,
        _metadata: TestcaseMetadata,
        _cache_store: &mut CS,
        _fallback_store: &mut FS,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
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
}
