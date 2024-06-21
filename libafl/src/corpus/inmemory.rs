//! In-memory corpus, keeps all test cases in memory at all times

use alloc::vec::Vec;
use core::cell::RefCell;

use serde::{Deserialize, Serialize};

use super::HasTestcase;
use crate::{
    corpus::{Corpus, CorpusId, Testcase},
    inputs::{Input, UsesInput},
    Error,
};

/// Keep track of the stored `Testcase` and the siblings ids (insertion order)
#[cfg(not(feature = "corpus_btreemap"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct TestcaseStorageItem<I>
where
    I: Input,
{
    /// The stored testcase
    pub testcase: RefCell<Testcase<I>>,
    /// Previously inserted id
    pub prev: Option<CorpusId>,
    /// Following inserted id
    pub next: Option<CorpusId>,
}

/// The map type in which testcases are stored (disable the feature `corpus_btreemap` to use a `HashMap` instead of `BTreeMap`)
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct TestcaseStorageMap<I>
where
    I: Input,
{
    #[cfg(not(feature = "corpus_btreemap"))]
    /// A map of `CorpusId` to `TestcaseStorageItem`
    pub map: hashbrown::HashMap<CorpusId, TestcaseStorageItem<I>>,
    #[cfg(feature = "corpus_btreemap")]
    /// A map of `CorpusId` to `Testcase`.
    pub map: alloc::collections::btree_map::BTreeMap<CorpusId, RefCell<Testcase<I>>>,
    /// The keys in order (use `Vec::binary_search`)
    pub keys: Vec<CorpusId>,
    /// First inserted id
    #[cfg(not(feature = "corpus_btreemap"))]
    first_id: Option<CorpusId>,
    /// Last inserted id
    #[cfg(not(feature = "corpus_btreemap"))]
    last_id: Option<CorpusId>,
}

impl<I> TestcaseStorageMap<I>
where
    I: Input,
{
    /// Insert a key in the keys set
    fn insert_key(&mut self, id: CorpusId) {
        if let Err(idx) = self.keys.binary_search(&id) {
            self.keys.insert(idx, id);
        }
    }

    /// Remove a key from the keys set
    fn remove_key(&mut self, id: CorpusId) {
        if let Ok(idx) = self.keys.binary_search(&id) {
            self.keys.remove(idx);
        }
    }

    /// Replace a testcase given a `CorpusId`
    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Option<Testcase<I>> {
        if let Some(entry) = self.map.get_mut(&id) {
            Some(entry.testcase.replace(testcase))
        } else {
            None
        }
    }

    /// Replace a testcase given a `CorpusId`
    #[cfg(feature = "corpus_btreemap")]
    pub fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Option<Testcase<I>> {
        self.map.get_mut(&id).map(|entry| entry.replace(testcase))
    }

    /// Remove a testcase given a [`CorpusId`]
    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn remove(&mut self, id: CorpusId) -> Option<RefCell<Testcase<I>>> {
        if let Some(item) = self.map.remove(&id) {
            self.remove_key(id);
            if let Some(prev) = item.prev {
                self.map.get_mut(&prev).unwrap().next = item.next;
            } else {
                // first elem
                self.first_id = item.next;
            }
            if let Some(next) = item.next {
                self.map.get_mut(&next).unwrap().prev = item.prev;
            } else {
                // last elem
                self.last_id = item.prev;
            }
            Some(item.testcase)
        } else {
            None
        }
    }

    /// Remove a testcase given a [`CorpusId`]
    #[cfg(feature = "corpus_btreemap")]
    pub fn remove(&mut self, id: CorpusId) -> Option<RefCell<Testcase<I>>> {
        self.remove_key(id);
        self.map.remove(&id)
    }

    /// Get a testcase given a `CorpusId`
    #[cfg(not(feature = "corpus_btreemap"))]
    #[must_use]
    pub fn get(&self, id: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        self.map.get(&id).as_ref().map(|x| &x.testcase)
    }

    /// Get a testcase given a `CorpusId`
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn get(&self, id: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        self.map.get(&id)
    }

    /// Get the next id given a `CorpusId` (creation order)
    #[cfg(not(feature = "corpus_btreemap"))]
    #[must_use]
    pub fn next(&self, id: CorpusId) -> Option<CorpusId> {
        if let Some(item) = self.map.get(&id) {
            item.next
        } else {
            None
        }
    }

    /// Get the next id given a `CorpusId` (creation order)
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn next(&self, id: CorpusId) -> Option<CorpusId> {
        // TODO see if using self.keys is faster
        let mut range = self
            .map
            .range((core::ops::Bound::Included(id), core::ops::Bound::Unbounded));
        if let Some((this_id, _)) = range.next() {
            if id != *this_id {
                return None;
            }
        }
        if let Some((next_id, _)) = range.next() {
            Some(*next_id)
        } else {
            None
        }
    }

    /// Get the previous id given a `CorpusId` (creation order)
    #[cfg(not(feature = "corpus_btreemap"))]
    #[must_use]
    pub fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        if let Some(item) = self.map.get(&id) {
            item.prev
        } else {
            None
        }
    }

    /// Get the previous id given a `CorpusId` (creation order)
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        // TODO see if using self.keys is faster
        let mut range = self
            .map
            .range((core::ops::Bound::Unbounded, core::ops::Bound::Included(id)));
        if let Some((this_id, _)) = range.next_back() {
            if id != *this_id {
                return None;
            }
        }
        if let Some((prev_id, _)) = range.next_back() {
            Some(*prev_id)
        } else {
            None
        }
    }

    /// Get the first created id
    #[cfg(not(feature = "corpus_btreemap"))]
    #[must_use]
    pub fn first(&self) -> Option<CorpusId> {
        self.first_id
    }

    /// Get the first created id
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn first(&self) -> Option<CorpusId> {
        self.map.iter().next().map(|x| *x.0)
    }

    /// Get the last created id
    #[cfg(not(feature = "corpus_btreemap"))]
    #[must_use]
    pub fn last(&self) -> Option<CorpusId> {
        self.last_id
    }

    /// Get the last created id
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn last(&self) -> Option<CorpusId> {
        self.map.iter().next_back().map(|x| *x.0)
    }

    fn new() -> Self {
        Self {
            #[cfg(not(feature = "corpus_btreemap"))]
            map: hashbrown::HashMap::default(),
            #[cfg(feature = "corpus_btreemap")]
            map: alloc::collections::BTreeMap::default(),
            keys: Vec::default(),
            #[cfg(not(feature = "corpus_btreemap"))]
            first_id: None,
            #[cfg(not(feature = "corpus_btreemap"))]
            last_id: None,
        }
    }
}
/// Storage map for the testcases (used in `Corpus` implementations) with an incremental index
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct TestcaseStorage<I>
where
    I: Input,
{
    /// The map in which enabled testcases are stored
    pub enabled: TestcaseStorageMap<I>,
    /// The map in which disabled testcases are stored
    pub disabled: TestcaseStorageMap<I>,
    /// The progressive id for both maps
    progressive_id: usize,
}

impl<I> UsesInput for TestcaseStorage<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> TestcaseStorage<I>
where
    I: Input,
{
    /// Insert a testcase assigning a `CorpusId` to it
    pub fn insert(&mut self, testcase: RefCell<Testcase<I>>) -> CorpusId {
        self._insert(testcase, false)
    }

    #[must_use]
    /// Peek the next free corpus id
    pub fn peek_free_id(&self) -> CorpusId {
        CorpusId::from(self.progressive_id)
    }

    /// Insert a testcase assigning a `CorpusId` to it
    pub fn insert_disabled(&mut self, testcase: RefCell<Testcase<I>>) -> CorpusId {
        self._insert(testcase, true)
    }

    /// Insert a testcase assigning a `CorpusId` to it
    #[cfg(not(feature = "corpus_btreemap"))]
    fn _insert(&mut self, testcase: RefCell<Testcase<I>>, is_disabled: bool) -> CorpusId {
        let id = CorpusId::from(self.progressive_id);
        self.progressive_id += 1;
        let corpus = if is_disabled {
            &mut self.disabled
        } else {
            &mut self.enabled
        };
        let prev = if let Some(last_id) = corpus.last_id {
            corpus.map.get_mut(&last_id).unwrap().next = Some(id);
            Some(last_id)
        } else {
            None
        };
        if corpus.first_id.is_none() {
            corpus.first_id = Some(id);
        }
        corpus.last_id = Some(id);
        corpus.insert_key(id);
        corpus.map.insert(
            id,
            TestcaseStorageItem {
                testcase,
                prev,
                next: None,
            },
        );
        id
    }

    /// Insert a testcase assigning a `CorpusId` to it
    #[cfg(feature = "corpus_btreemap")]
    fn _insert(&mut self, testcase: RefCell<Testcase<I>>, is_disabled: bool) -> CorpusId {
        let id = CorpusId::from(self.progressive_id);
        self.progressive_id += 1;
        let corpus = if is_disabled {
            &mut self.disabled
        } else {
            &mut self.enabled
        };
        corpus.insert_key(id);
        corpus.map.insert(id, testcase);
        id
    }

    /// Create new `TestcaseStorage`
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: TestcaseStorageMap::new(),
            disabled: TestcaseStorageMap::new(),
            progressive_id: 0,
        }
    }
}

/// A corpus handling all in memory.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct InMemoryCorpus<I>
where
    I: Input,
{
    storage: TestcaseStorage<I>,
    current: Option<CorpusId>,
}

impl<I> UsesInput for InMemoryCorpus<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> Corpus for InMemoryCorpus<I>
where
    I: Input,
{
    /// Returns the number of all enabled entries
    #[inline]
    fn count(&self) -> usize {
        self.storage.enabled.map.len()
    }

    /// Returns the number of all disabled entries
    fn count_disabled(&self) -> usize {
        self.storage.disabled.map.len()
    }

    /// Returns the number of elements including disabled entries
    #[inline]
    fn count_all(&self) -> usize {
        self.storage
            .enabled
            .map
            .len()
            .saturating_add(self.storage.disabled.map.len())
    }

    /// Add an enabled testcase to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        Ok(self.storage.insert(RefCell::new(testcase)))
    }

    /// Add a disabled testcase to the corpus and return its index
    #[inline]
    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        Ok(self.storage.insert_disabled(RefCell::new(testcase)))
    }

    /// Replaces the testcase at the given id
    #[inline]
    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        self.storage.enabled.replace(id, testcase).ok_or_else(|| {
            Error::key_not_found(format!("Index {id} not found, could not replace."))
        })
    }

    /// Removes an entry from the corpus, returning it if it was present; considers both enabled and disabled testcases
    #[inline]
    fn remove(&mut self, id: CorpusId) -> Result<Testcase<Self::Input>, Error> {
        let mut testcase = self.storage.enabled.remove(id);
        if testcase.is_none() {
            testcase = self.storage.disabled.remove(id);
        }
        testcase
            .map(|x| x.take())
            .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))
    }

    /// Get by id; considers only enabled testcases
    #[inline]
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.storage
            .enabled
            .get(id)
            .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))
    }
    /// Get by id; considers both enabled and disabled testcases
    #[inline]
    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error> {
        let mut testcase = self.storage.enabled.get(id);
        if testcase.is_none() {
            testcase = self.storage.disabled.get(id);
        }
        testcase.ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    /// Peek the next free corpus id
    #[inline]
    fn peek_free_id(&self) -> CorpusId {
        self.storage.peek_free_id()
    }

    #[inline]
    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.storage.enabled.next(id)
    }

    #[inline]
    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.storage.enabled.prev(id)
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        self.storage.enabled.first()
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        self.storage.enabled.last()
    }

    /// Get the nth corpus id; considers only enabled testcases
    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        self.storage.enabled.keys[nth]
    }

    /// Get the nth corpus id; considers both enabled and disabled testcases
    #[inline]
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        let enabled_count = self.count();
        if nth >= enabled_count {
            return self.storage.disabled.keys[nth.saturating_sub(enabled_count)];
        }
        self.storage.enabled.keys[nth]
    }

    #[inline]
    fn load_input_into(&self, _: &mut Testcase<Self::Input>) -> Result<(), Error> {
        // Inputs never get evicted, nothing to load here.
        Ok(())
    }

    #[inline]
    fn store_input_from(&self, _: &Testcase<Self::Input>) -> Result<(), Error> {
        Ok(())
    }
}

impl<I> HasTestcase for InMemoryCorpus<I>
where
    I: Input,
{
    fn testcase(
        &self,
        id: CorpusId,
    ) -> Result<core::cell::Ref<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.get(id)?.borrow())
    }

    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<core::cell::RefMut<Testcase<<Self as UsesInput>::Input>>, Error> {
        Ok(self.get(id)?.borrow_mut())
    }
}

impl<I> InMemoryCorpus<I>
where
    I: Input,
{
    /// Creates a new [`InMemoryCorpus`], keeping all [`Testcase`]`s` in memory.
    /// This is the simplest and fastest option, however test progress will be lost on exit or on OOM.
    #[must_use]
    pub fn new() -> Self {
        Self {
            storage: TestcaseStorage::new(),
            current: None,
        }
    }
}
