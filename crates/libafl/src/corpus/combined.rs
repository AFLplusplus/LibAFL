//! A cached corpus, using a given [`Cache`] policy and two [`Store`]s.

use alloc::rc::Rc;
use core::{cell::RefCell, marker::PhantomData};
use std::vec::Vec;

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use super::{Cache, Corpus, CorpusCounter, CorpusId, Testcase, store::Store};
use crate::corpus::testcase::TestcaseMetadata;

/// A [`CombinedCorpus`] tries first to use the main store according to some policy.
/// If it fails, it falls back to the secondary store.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct CombinedCorpus<C, CS, FS, I> {
    /// The cache store
    cache_store: RefCell<CS>,
    /// The fallback store
    fallback_store: FS,
    /// The policty taking decisions
    cache: RefCell<C>,
    /// The corpus ID counter
    counter: CorpusCounter,
    /// The keys in order (use `Vec::binary_search`)
    keys: Vec<CorpusId>,
    /// The current ID
    current: Option<CorpusId>,
    phantom: PhantomData<I>,
}

impl<C, CS, FS, I> Corpus<I> for CombinedCorpus<C, CS, FS, I>
where
    C: Cache<CS, FS, I, TestcaseMetadataCell = CS::TestcaseMetadataCell>,
    CS: Store<I>,
    FS: Store<I>,
    I: Clone,
{
    type TestcaseMetadataCell = CS::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.fallback_store.count()
    }

    fn count_disabled(&self) -> usize {
        self.fallback_store.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.fallback_store.count_all()
    }

    fn add(&mut self, input: Rc<I>, md: TestcaseMetadata) -> Result<CorpusId, Error> {
        let new_id = self.counter.new_id();

        self.cache.borrow_mut().add(
            new_id,
            input,
            md,
            &mut *self.cache_store.borrow_mut(),
            &mut self.fallback_store,
        )?;

        Ok(new_id)
    }

    fn add_disabled(&mut self, input: Rc<I>, md: TestcaseMetadata) -> Result<CorpusId, Error> {
        let new_id = self.counter.new_id();

        self.cache.borrow_mut().add_disabled(
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

    fn replace(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.cache.borrow_mut().replace(
            id,
            input,
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
