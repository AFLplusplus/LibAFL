//! A simple corpus, with a backing store.
//!
//! A [`SingleCorpus`] owns a single store, in which every testcase is added.

use alloc::rc::Rc;
use core::marker::PhantomData;
use std::vec::Vec;

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use super::{Corpus, CorpusCounter, CorpusId, Testcase, store::Store};
use crate::corpus::testcase::TestcaseMetadata;

/// You average corpus.
/// It has one backing store, used to store / retrieve testcases.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SingleCorpus<I, S> {
    /// The backing testcase store
    store: S,
    /// The corpus ID counter
    counter: CorpusCounter,
    /// The keys in order (use `Vec::binary_search`)
    keys: Vec<CorpusId>,
    /// The current ID
    current: Option<CorpusId>,
    phantom: PhantomData<I>,
}

impl<I, S> Default for SingleCorpus<I, S>
where
    S: Default,
{
    fn default() -> Self {
        Self {
            store: S::default(),
            counter: CorpusCounter::default(),
            keys: Vec::new(),
            current: None,
            phantom: PhantomData,
        }
    }
}

impl<I, S> SingleCorpus<I, S>
where
    S: Default,
{
    /// Create a new [`SingleCorpus`]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I, S> Corpus<I> for SingleCorpus<I, S>
where
    S: Store<I>,
{
    type TestcaseMetadataCell = S::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.store.count()
    }

    fn count_disabled(&self) -> usize {
        self.store.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.store.count_all()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error> {
        let new_id = self.counter.new_id();
        self.store.add_shared::<ENABLED>(new_id, input, md)?;
        Ok(new_id)
    }

    /// Get testcase by id
    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.store.get_from::<ENABLED>(id)
    }

    fn replace_metadata(
        &mut self,
        id: CorpusId,
        md: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        self.store.replace_metadata(id, md)
    }

    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.store.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.store.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.store.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.store.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.store.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.store.nth_from_all(nth)
    }
}
