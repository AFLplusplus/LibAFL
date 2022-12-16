//! Corpuses contain the testcases, either in memory, on disk, or somewhere else.

pub mod testcase;
pub use testcase::{SchedulerTestcaseMetaData, Testcase};

pub mod inmemory;
pub use inmemory::InMemoryCorpus;

#[cfg(feature = "std")]
pub mod ondisk;
#[cfg(feature = "std")]
pub use ondisk::OnDiskCorpus;

#[cfg(feature = "std")]
pub mod cached;
#[cfg(feature = "std")]
pub use cached::CachedOnDiskCorpus;

#[cfg(feature = "cmin")]
pub mod minimizer;
use core::cell::RefCell;

#[cfg(feature = "cmin")]
pub use minimizer::*;
use serde::{Deserialize, Serialize};

use crate::{
    inputs::{Input, UsesInput},
    Error,
};

/// Corpus with all current testcases
pub trait Corpus: UsesInput + Serialize + for<'de> Deserialize<'de> {
    /// Returns the number of elements
    fn count(&self) -> usize;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Add an entry to the corpus and return its index
    fn add(&mut self, testcase: Testcase<Self::Input>) -> Result<CorpusId, Error>;

    /// Replaces the testcase at the given idx, returning the existing.
    fn replace(
        &mut self,
        idx: CorpusId,
        testcase: Testcase<Self::Input>,
    ) -> Result<Testcase<Self::Input>, Error>;

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, idx: CorpusId) -> Result<Option<Testcase<Self::Input>>, Error>;

    /// Get by id
    fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error>;

    /// Current testcase scheduled
    fn current(&self) -> &Option<CorpusId>;

    /// Current testcase scheduled (mutable)
    fn current_mut(&mut self) -> &mut Option<CorpusId>;
}

/// An abstraction for the index that identify a testcase in the corpus
#[derive(
    Debug,
    Clone, Copy,
    PartialEq, Eq,
    Hash,
    PartialOrd, Ord,
    Serialize, Deserialize
)]
#[repr(transparent)]
pub struct CorpusId(usize);

impl CorpusId {
    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn next<I>(&self, storage: &TestcaseStorage<I>) -> Option<CorpusId> where
    I: Input,{
        if let Some(item) = storage.map.get(self) {
            item.next
        } else {
            None
        }
    }

    #[cfg(feature = "corpus_btreemap")]
    pub fn next<I>(&self, storage: &TestcaseStorage<I>) -> Option<CorpusId> where
    I: Input,{
        let mut range = storage.map.range(core::ops::Bound::Included(self), core::ops::Bound::Unbounded);
        if let Some((self_id, _)) = range.next() {
            if self != self_id {
                return None;
            }
        }
        if let Some((next_id, _)) = range.next() {
            Some(next_id)
        } else {
            None
        }
    }

    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn prev<I>(&self, storage: &TestcaseStorage<I>) -> Option<CorpusId> where
    I: Input,{
        if let Some(item) = storage.map.get(self) {
            item.prev
        } else {
            None
        }
    }

    #[cfg(feature = "corpus_btreemap")]
    pub fn prev<I>(&self, storage: &TestcaseStorage<I>) -> Option<CorpusId> where
    I: Input,{
        let mut range = storage.map.range(core::ops::Bound::Unbounded, core::ops::Bound::Included(self));
        if let Some((self_id, _)) = range.next_back() {
            if self != self_id {
                return None;
            }
        }
        if let Some((prev_id, _)) = range.next_back() {
            Some(prev_id)
        } else {
            None
        }
    }
}

impl From<usize> for CorpusId {
    fn from(id: usize) -> Self {
        Self(id)
    }
}

#[cfg(not(feature = "corpus_btreemap"))]
pub struct TestcaseStorageItem<I> where
    I: Input, {
    pub testcase: RefCell<Testcase<I>>,
    pub prev: Option<CorpusId>,
    pub next: Option<CorpusId>
}

#[cfg(not(feature = "corpus_btreemap"))]
/// The map type in which testcases are stored (enable the feature 'corpus_btreemap' to use a `BTreeMap` instead of `HashMap`)
pub type TestcaseStorageMap<I> = hashbrown::HashMap<CorpusId, TestcaseStorageItem<I>>;

#[cfg(feature = "corpus_btreemap")]
/// The map type in which testcases are stored (disable the feature 'corpus_btreemap' to use a `HashMap` instead of `BTreeMap`)
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
    /// The progressive idx
    progressive_idx: usize,
    /// Last inserted idx
    #[cfg(not(feature = "corpus_btreemap"))]
    last_idx: CorpusId,
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
        self.map.insert(idx, TestcaseStorageItem { testcase, prev, next: None });
        idx
    }

    /// Insert a testcase assigning a `CorpusId` to it
    #[cfg(feature = "corpus_btreemap")]
    pub fn insert(&mut self, testcase: RefCell<Testcase<I>>) -> CorpusId {
        let idx = CorpusId::from(self.progressive_idx);
        self.progressive_idx += 1;
        self.map.insert(idx, testcase);
        idx
    }
    
    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn remove(&self, idx: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        if let Some(item) = self.map.remove(&idx) {
            if let Some(prev) = item.prev {
                self.map.get(&prev).unwrap().next = item.next;
            }
            if let Some(next) = item.next {
                self.map.get(&next).unwrap().prev = item.prev;
            }
            Some(item)
        } else {
            None
        }
    }

    #[cfg(feature = "corpus_btreemap")]
    pub fn remove(&self, idx: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        self.map.remove(&idx)
    }

    #[cfg(not(feature = "corpus_btreemap"))]
    pub fn get(&self, idx: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        self.map.get(&idx)
    }

    #[cfg(feature = "corpus_btreemap")]
    pub fn get(&self, idx: CorpusId) -> Option<&RefCell<Testcase<I>>> {
        self.map.get(&idx).map(|x| x.testcase)
    }

    /// Create new
    pub fn new() -> Self {
        Self {
            map: TestcaseStorageMap::default(),
            progressive_idx: 0,
        }
    }
}

/// `Corpus` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use std::cell::RefCell;

    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    use crate::{
        corpus::{
            cached::pybind::PythonCachedOnDiskCorpus, inmemory::pybind::PythonInMemoryCorpus,
            ondisk::pybind::PythonOnDiskCorpus, testcase::pybind::PythonTestcaseWrapper, Corpus,
            Testcase,
        },
        inputs::{BytesInput, UsesInput},
        Error,
    };

    #[derive(Serialize, Deserialize, Debug, Clone)]
    enum PythonCorpusWrapper {
        InMemory(Py<PythonInMemoryCorpus>),
        CachedOnDisk(Py<PythonCachedOnDiskCorpus>),
        OnDisk(Py<PythonOnDiskCorpus>),
    }

    /// Corpus Trait binding
    #[pyclass(unsendable, name = "Corpus")]
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PythonCorpus {
        wrapper: PythonCorpusWrapper,
    }

    macro_rules! unwrap_me {
        ($wrapper:expr, $name:ident, $body:block) => {
            crate::unwrap_me_body!(
                $wrapper,
                $name,
                $body,
                PythonCorpusWrapper,
                {
                    InMemory,
                    CachedOnDisk,
                    OnDisk
                }
            )
        };
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            crate::unwrap_me_mut_body!(
                $wrapper,
                $name,
                $body,
                PythonCorpusWrapper,
                {
                    InMemory,
                    CachedOnDisk,
                    OnDisk
                }
            )
        };
    }

    #[pymethods]
    impl PythonCorpus {
        #[staticmethod]
        #[must_use]
        pub fn new_in_memory(py_in_memory_corpus: Py<PythonInMemoryCorpus>) -> Self {
            Self {
                wrapper: PythonCorpusWrapper::InMemory(py_in_memory_corpus),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_cached_on_disk(py_cached_on_disk_corpus: Py<PythonCachedOnDiskCorpus>) -> Self {
            Self {
                wrapper: PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus),
            }
        }

        #[staticmethod]
        #[must_use]
        pub fn new_on_disk(py_on_disk_corpus: Py<PythonOnDiskCorpus>) -> Self {
            Self {
                wrapper: PythonCorpusWrapper::OnDisk(py_on_disk_corpus),
            }
        }

        #[pyo3(name = "count")]
        fn pycount(&self) -> usize {
            self.count()
        }

        #[pyo3(name = "current")]
        fn pycurrent(&self) -> Option<usize> {
            *self.current()
        }

        #[pyo3(name = "get")]
        fn pyget(&self, idx: usize) -> PythonTestcaseWrapper {
            let t: &mut Testcase<BytesInput> = unwrap_me!(self.wrapper, c, {
                c.get(idx)
                    .map(|v| unsafe { v.as_ptr().as_mut().unwrap() })
                    .expect("PythonCorpus::get failed")
            });
            PythonTestcaseWrapper::wrap(t)
        }
    }

    impl UsesInput for PythonCorpus {
        type Input = BytesInput;
    }

    impl Corpus for PythonCorpus {
        #[inline]
        fn count(&self) -> usize {
            unwrap_me!(self.wrapper, c, { c.count() })
        }

        #[inline]
        fn add(&mut self, testcase: Testcase<BytesInput>) -> Result<usize, Error> {
            unwrap_me_mut!(self.wrapper, c, { c.add(testcase) })
        }

        #[inline]
        fn replace(
            &mut self,
            idx: usize,
            testcase: Testcase<BytesInput>,
        ) -> Result<Testcase<BytesInput>, Error> {
            unwrap_me_mut!(self.wrapper, c, { c.replace(idx, testcase) })
        }

        #[inline]
        fn remove(&mut self, idx: usize) -> Result<Option<Testcase<BytesInput>>, Error> {
            unwrap_me_mut!(self.wrapper, c, { c.remove(idx) })
        }

        #[inline]
        fn get(&self, idx: usize) -> Result<&RefCell<Testcase<BytesInput>>, Error> {
            let ptr = unwrap_me!(self.wrapper, c, {
                c.get(idx)
                    .map(|v| v as *const RefCell<Testcase<BytesInput>>)
            })?;
            Ok(unsafe { ptr.as_ref().unwrap() })
        }

        #[inline]
        fn current(&self) -> &Option<usize> {
            let ptr = unwrap_me!(self.wrapper, c, { c.current() as *const Option<usize> });
            unsafe { ptr.as_ref().unwrap() }
        }

        #[inline]
        fn current_mut(&mut self) -> &mut Option<usize> {
            let ptr = unwrap_me_mut!(self.wrapper, c, { c.current_mut() as *mut Option<usize> });
            unsafe { ptr.as_mut().unwrap() }
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonCorpus>()?;
        Ok(())
    }
}
