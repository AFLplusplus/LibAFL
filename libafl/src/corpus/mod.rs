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
#[cfg(feature = "cmin")]
pub use minimizer::*;

use core::{fmt, cell::RefCell};
use serde::{Deserialize, Serialize};

use crate::{
bolts::rands::Rand,
    inputs::{Input, UsesInput},
    Error,
};

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
pub struct CorpusId(pub(crate) usize);

impl fmt::Display for CorpusId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CorpusId({})", self.0)
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
    
    /// Get the next corpus id
    fn next(&self, idx: CorpusId) -> Option<CorpusId>;
    
    /// Get the prev corpus id
    fn prev(&self, idx: CorpusId) -> Option<CorpusId>;

    /// Get the first inserted corpus id
    fn first(&self) -> Option<CorpusId>;

    /// Get the last inserted corpus id
    fn last(&self) -> Option<CorpusId>;
    
    fn indexes<'a>(&'a self) -> CorpusIdIterator<'a, Self> {
        CorpusIdIterator { corpus: self, cur: self.first() }
    }

    fn random_index<R>(&'a self, rnd: &mut R) -> CorpusId where R: Rand {
        let nth = rand.below(self.count() as u64) as usize;
        self.indexes().nth(nth).expect("Failed to get a random CorpusId")
    }
}

pub struct CorpusIdIterator<'a, C> where C: Corpus {
    corpus: &'a C,
    cur: Option<CorpusId>
}

impl<'a, C> Iterator for CorpusIdIterator<'a, C> where C: Corpus {
    type Item = CorpusId;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(cur) = self.cur {
            self.cur = self.corpus.next(cur);
            self.cur
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
