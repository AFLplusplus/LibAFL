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

#[cfg(not(feature = "corpus_btreemap"))]
/// The map type in which testcases are stored (enable the feature `corpus_btreemap` to use a `BTreeMap` instead of `HashMap`)
pub type TestcaseStorageMap<I> = hashbrown::HashMap<CorpusId, TestcaseStorageItem<I>>;

#[cfg(feature = "corpus_btreemap")]
/// The map type in which testcases are stored (disable the feature `corpus_btreemap` to use a `HashMap` instead of `BTreeMap`)
pub type TestcaseStorageMap<I> =
    alloc::collections::btree_map::BTreeMap<CorpusId, RefCell<Testcase<I>>>;

/// Storage map for the testcases (used in `Corpus` implementations) with an incremental index
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct TestcaseStorage<I>
where
    I: Input,
{
    /// The map in which testcases are stored
    pub map: TestcaseStorageMap<I>,
    /// The keys in order (use `Vec::binary_search`)
    pub keys: Vec<CorpusId>,
    /// The progressive idx
    progressive_idx: usize,
    /// First inserted idx
    #[cfg(not(feature = "corpus_btreemap"))]
    first_idx: Option<CorpusId>,
    /// Last inserted idx
    #[cfg(not(feature = "corpus_btreemap"))]
    last_idx: Option<CorpusId>,
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

    /// Insert a testcase assigning a `CorpusId` to it
    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn insert(&mut self, testcase: RefCell<Testcase<I>>) -> CorpusId {
        let idx = CorpusId::from(self.progressive_idx);
        self.progressive_idx += 1;
        let prev = if let Some(last_idx) = self.last_idx {
            self.map.get_mut(&last_idx).unwrap().next = Some(idx);
            Some(last_idx)
        } else {
            None
        };
        if self.first_idx.is_none() {
            self.first_idx = Some(idx);
        }
        self.last_idx = Some(idx);
        self.insert_key(idx);
        self.map.insert(
            idx,
            TestcaseStorageItem {
                testcase,
                prev,
                next: None,
            },
        );
        idx
    }

    /// Insert a testcase assigning a `CorpusId` to it
    #[cfg(feature = "corpus_btreemap")]
    pub fn insert(&mut self, testcase: RefCell<Testcase<I>>) -> CorpusId {
        let idx = CorpusId::from(self.progressive_idx);
        self.progressive_idx += 1;
        self.insert_key(idx);
        self.map.insert(idx, testcase);
        idx
    }

    /// Replace a testcase given a `CorpusId`
    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Option<Testcase<I>> {
        if let Some(entry) = self.map.get_mut(&idx) {
            Some(entry.testcase.replace(testcase))
        } else {
            None
        }
    }

    /// Replace a testcase given a `CorpusId`
    #[cfg(feature = "corpus_btreemap")]
    pub fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Option<Testcase<I>> {
        self.map.get_mut(&idx).map(|entry| entry.replace(testcase))
    }

    /// Remove a testcase given a `CorpusId`
    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn remove(&mut self, idx: CorpusId) -> Option<RefCell<Testcase<I>>> {
        if let Some(item) = self.map.remove(&idx) {
            self.remove_key(idx);
            if let Some(prev) = item.prev {
                self.map.get_mut(&prev).unwrap().next = item.next;
            } else {
                // first elem
                self.first_idx = item.next;
            }
            if let Some(next) = item.next {
                self.map.get_mut(&next).unwrap().prev = item.prev;
            } else {
                // last elem
                self.last_idx = item.prev;
            }
            Some(item.testcase)
        } else {
            None
        }
    }

    /// Remove a testcase given a `CorpusId`
    #[cfg(feature = "corpus_btreemap")]
    pub fn remove(&mut self, idx: CorpusId) -> Option<RefCell<Testcase<I>>> {
        self.remove_key(idx);
        self.map.remove(&idx)
    }

    /// Get a testcase given a `CorpusId`
    #[cfg(not(feature = "corpus_btreemap"))]
    #[must_use]
    pub fn get(&self, idx: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        self.map.get(&idx).as_ref().map(|x| &x.testcase)
    }

    /// Get a testcase given a `CorpusId`
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn get(&self, idx: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        self.map.get(&idx)
    }

    /// Get the next id given a `CorpusId` (creation order)
    #[cfg(not(feature = "corpus_btreemap"))]
    #[must_use]
    pub fn next(&self, idx: CorpusId) -> Option<CorpusId> {
        if let Some(item) = self.map.get(&idx) {
            item.next
        } else {
            None
        }
    }

    /// Get the next id given a `CorpusId` (creation order)
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn next(&self, idx: CorpusId) -> Option<CorpusId> {
        // TODO see if using self.keys is faster
        let mut range = self
            .map
            .range((core::ops::Bound::Included(idx), core::ops::Bound::Unbounded));
        if let Some((this_id, _)) = range.next() {
            if idx != *this_id {
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
    pub fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
        if let Some(item) = self.map.get(&idx) {
            item.prev
        } else {
            None
        }
    }

    /// Get the previous id given a `CorpusId` (creation order)
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
        // TODO see if using self.keys is faster
        let mut range = self
            .map
            .range((core::ops::Bound::Unbounded, core::ops::Bound::Included(idx)));
        if let Some((this_id, _)) = range.next_back() {
            if idx != *this_id {
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
        self.first_idx
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
        self.last_idx
    }

    /// Get the last created id
    #[cfg(feature = "corpus_btreemap")]
    #[must_use]
    pub fn last(&self) -> Option<CorpusId> {
        self.map.iter().next_back().map(|x| *x.0)
    }

    /// Create new `TestcaseStorage`
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: TestcaseStorageMap::default(),
            keys: vec![],
            progressive_idx: 0,
            #[cfg(not(feature = "corpus_btreemap"))]
            first_idx: None,
            #[cfg(not(feature = "corpus_btreemap"))]
            last_idx: None,
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
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.storage.map.len()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        Ok(self.storage.insert(RefCell::new(testcase)))
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        self.storage
            .replace(idx, testcase)
            .ok_or_else(|| Error::key_not_found(format!("Index {idx} not found")))
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: CorpusId) -> Result<Testcase<I>, Error> {
        self.storage
            .remove(idx)
            .map(|x| x.take())
            .ok_or_else(|| Error::key_not_found(format!("Index {idx} not found")))
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.storage
            .get(idx)
            .ok_or_else(|| Error::key_not_found(format!("Index {idx} not found")))
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

    #[inline]
    fn next(&self, idx: CorpusId) -> Option<CorpusId> {
        self.storage.next(idx)
    }

    #[inline]
    fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
        self.storage.prev(idx)
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        self.storage.first()
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        self.storage.last()
    }

    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        self.storage.keys[nth]
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

/// `InMemoryCorpus` Python bindings
#[cfg(feature = "python")]
#[allow(clippy::unnecessary_fallible_conversions, unused_qualifications)]
pub mod pybind {
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    use crate::{
        corpus::{pybind::PythonCorpus, InMemoryCorpus},
        inputs::BytesInput,
    };

    #[pyclass(unsendable, name = "InMemoryCorpus")]
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    /// Python class for InMemoryCorpus
    pub struct PythonInMemoryCorpus {
        /// Rust wrapped InMemoryCorpus object
        pub inner: InMemoryCorpus<BytesInput>,
    }

    #[pymethods]
    impl PythonInMemoryCorpus {
        #[new]
        fn new() -> Self {
            Self {
                inner: InMemoryCorpus::new(),
            }
        }

        fn as_corpus(slf: Py<Self>) -> PythonCorpus {
            PythonCorpus::new_in_memory(slf)
        }
    }
    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonInMemoryCorpus>()?;
        Ok(())
    }
}
