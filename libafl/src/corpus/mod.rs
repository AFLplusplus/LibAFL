//! Corpuses contain the testcases, either in memory, on disk, or somewhere else.

pub mod testcase;
pub use testcase::{HasTestcase, SchedulerTestcaseMetadata, Testcase};

pub mod inmemory;
pub use inmemory::InMemoryCorpus;

#[cfg(feature = "std")]
pub mod inmemory_ondisk;
#[cfg(feature = "std")]
pub use inmemory_ondisk::InMemoryOnDiskCorpus;

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
use core::{cell::RefCell, fmt};

pub mod nop;
#[cfg(feature = "cmin")]
pub use minimizer::*;
pub use nop::NopCorpus;
use serde::{Deserialize, Serialize};

use crate::{inputs::UsesInput, Error};

/// An abstraction for the index that identify a testcase in the corpus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CorpusId(pub(crate) usize);

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

/// Utility macro to call `Corpus::random_id`
#[macro_export]
macro_rules! random_corpus_id {
    ($corpus:expr, $rand:expr) => {{
        let cnt = $corpus.count() as u64;
        let nth = $rand.below(cnt) as usize;
        $corpus.nth(nth)
    }};
}

/// Corpus with all current [`Testcase`]s, or solutions
pub trait Corpus: UsesInput + Serialize + for<'de> Deserialize<'de> {
    /// Returns the number of elements
    fn count(&self) -> usize;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Add an entry to the corpus and return its index
    fn add(&mut self, testcase: Testcase<Self::Input>) -> Result<CorpusId, Error>;

    /// Replaces the [`Testcase`] at the given idx, returning the existing.
    fn replace(
        &mut self,
        idx: CorpusId,
        testcase: Testcase<Self::Input>,
    ) -> Result<Testcase<Self::Input>, Error>;

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, id: CorpusId) -> Result<Testcase<Self::Input>, Error>;

    /// Get by id
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error>;

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
    fn ids(&self) -> CorpusIdIterator<'_, Self> {
        CorpusIdIterator {
            corpus: self,
            cur: self.first(),
            cur_back: self.last(),
        }
    }

    /// Get the nth corpus id
    fn nth(&self, nth: usize) -> CorpusId {
        self.ids()
            .nth(nth)
            .expect("Failed to get the {nth} CorpusId")
    }

    /// Method to load the input for this [`Testcase`] from persistent storage,
    /// if necessary, and if was not already loaded (`== Some(input)`).
    /// After this call, `testcase.input()` must always return `Some(input)`.
    fn load_input_into(&self, testcase: &mut Testcase<Self::Input>) -> Result<(), Error>;

    /// Method to store the input of this `Testcase` to persistent storage, if necessary.
    fn store_input_from(&self, testcase: &Testcase<Self::Input>) -> Result<(), Error>;

    /// Loads the `Input` for a given [`CorpusId`] from the [`Corpus`], and returns the clone.
    fn cloned_input_for_id(&self, idx: CorpusId) -> Result<Self::Input, Error> {
        let mut testcase = self.get(idx)?.borrow_mut();
        Ok(testcase.load_input(self)?.clone())
    }
}

/// Trait for types which track the current corpus index
pub trait HasCurrentCorpusIdx {
    /// Set the current corpus index; we have started processing this corpus entry
    fn set_corpus_idx(&mut self, idx: CorpusId) -> Result<(), Error>;

    /// Clear the current corpus index; we are done with this entry
    fn clear_corpus_idx(&mut self) -> Result<(), Error>;

    /// Fetch the current corpus index -- typically used after a state recovery or transfer
    fn current_corpus_idx(&self) -> Result<Option<CorpusId>, Error>;
}

/// [`Iterator`] over the ids of a [`Corpus`]
#[derive(Debug)]
pub struct CorpusIdIterator<'a, C>
where
    C: Corpus,
{
    corpus: &'a C,
    cur: Option<CorpusId>,
    cur_back: Option<CorpusId>,
}

impl<'a, C> Iterator for CorpusIdIterator<'a, C>
where
    C: Corpus,
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

impl<'a, C> DoubleEndedIterator for CorpusIdIterator<'a, C>
where
    C: Corpus,
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
            inmemory_ondisk::pybind::PythonInMemoryOnDiskCorpus,
            ondisk::pybind::PythonOnDiskCorpus, testcase::pybind::PythonTestcaseWrapper, Corpus,
            CorpusId, HasTestcase, Testcase,
        },
        inputs::{BytesInput, UsesInput},
        Error,
    };

    #[derive(Serialize, Deserialize, Debug, Clone)]
    enum PythonCorpusWrapper {
        InMemory(Py<PythonInMemoryCorpus>),
        CachedOnDisk(Py<PythonCachedOnDiskCorpus>),
        OnDisk(Py<PythonOnDiskCorpus>),
        InMemoryOnDisk(Py<PythonInMemoryOnDiskCorpus>),
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
            libafl_bolts::unwrap_me_body!(
                $wrapper,
                $name,
                $body,
                PythonCorpusWrapper,
                {
                    InMemory,
                    InMemoryOnDisk,
                    CachedOnDisk,
                    OnDisk
                }
            )
        };
    }

    macro_rules! unwrap_me_mut {
        ($wrapper:expr, $name:ident, $body:block) => {
            libafl_bolts::unwrap_me_mut_body!(
                $wrapper,
                $name,
                $body,
                PythonCorpusWrapper,
                {
                    InMemory,
                    InMemoryOnDisk,
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

        #[staticmethod]
        #[must_use]
        pub fn new_in_memory_on_disk(
            py_in_memory_on_disk_corpus: Py<PythonInMemoryOnDiskCorpus>,
        ) -> Self {
            Self {
                wrapper: PythonCorpusWrapper::InMemoryOnDisk(py_in_memory_on_disk_corpus),
            }
        }

        #[pyo3(name = "count")]
        fn pycount(&self) -> usize {
            self.count()
        }

        #[pyo3(name = "current")]
        fn pycurrent(&self) -> Option<usize> {
            self.current().map(|x| x.0)
        }

        #[pyo3(name = "get")]
        fn pyget(&self, idx: usize) -> PythonTestcaseWrapper {
            let t: &mut Testcase<BytesInput> = unwrap_me!(self.wrapper, c, {
                c.get(CorpusId::from(idx))
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
        fn add(&mut self, testcase: Testcase<BytesInput>) -> Result<CorpusId, Error> {
            unwrap_me_mut!(self.wrapper, c, { c.add(testcase) })
        }

        #[inline]
        fn replace(
            &mut self,
            idx: CorpusId,
            testcase: Testcase<BytesInput>,
        ) -> Result<Testcase<BytesInput>, Error> {
            unwrap_me_mut!(self.wrapper, c, { c.replace(idx, testcase) })
        }

        #[inline]
        fn remove(&mut self, idx: CorpusId) -> Result<Testcase<BytesInput>, Error> {
            unwrap_me_mut!(self.wrapper, c, { c.remove(idx) })
        }

        #[inline]
        fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<BytesInput>>, Error> {
            let ptr = unwrap_me!(self.wrapper, c, {
                c.get(idx)
                    .map(core::ptr::from_ref::<RefCell<Testcase<BytesInput>>>)
            })?;
            Ok(unsafe { ptr.as_ref().unwrap() })
        }

        #[inline]
        fn current(&self) -> &Option<CorpusId> {
            let ptr = unwrap_me!(self.wrapper, c, { core::ptr::from_ref(c.current()) });
            unsafe { ptr.as_ref().unwrap() }
        }

        #[inline]
        fn current_mut(&mut self) -> &mut Option<CorpusId> {
            let ptr = unwrap_me_mut!(self.wrapper, c, { core::ptr::from_mut(c.current_mut()) });
            unsafe { ptr.as_mut().unwrap() }
        }

        fn next(&self, idx: CorpusId) -> Option<CorpusId> {
            unwrap_me!(self.wrapper, c, { c.next(idx) })
        }

        fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
            unwrap_me!(self.wrapper, c, { c.prev(idx) })
        }

        fn first(&self) -> Option<CorpusId> {
            unwrap_me!(self.wrapper, c, { c.first() })
        }

        fn last(&self) -> Option<CorpusId> {
            unwrap_me!(self.wrapper, c, { c.last() })
        }

        fn load_input_into(&self, testcase: &mut Testcase<BytesInput>) -> Result<(), Error> {
            unwrap_me!(self.wrapper, c, { c.load_input_into(testcase) })
        }

        fn store_input_from(&self, testcase: &Testcase<BytesInput>) -> Result<(), Error> {
            unwrap_me!(self.wrapper, c, { c.store_input_from(testcase) })
        }

        /*fn ids<'a>(&'a self) -> CorpusIdIterator<'a, Self> {
            CorpusIdIterator {
                corpus: self,
                cur: self.first(),
                cur_back: self.last(),
            }
        }

        fn random_id(&self, next_random: u64) -> CorpusId {
            let nth = (next_random as usize) % self.count();
            self.ids()
                .nth(nth)
                .expect("Failed to get a random CorpusId")
        }*/
    }

    impl HasTestcase for PythonCorpus {
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

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonCorpus>()?;
        Ok(())
    }
}
