//! Corpuses contain the testcases, either in memory, on disk, or somewhere else.

pub mod testcase;
pub use testcase::{PowerScheduleTestcaseMetaData, Testcase};

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

use core::cell::RefCell;

use crate::{inputs::Input, Error};

/// Corpus with all current testcases
pub trait Corpus<I>: serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
{
    /// Returns the number of elements
    fn count(&self) -> usize;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Add an entry to the corpus and return its index
    fn add(&mut self, testcase: Testcase<I>) -> Result<usize, Error>;

    /// Replaces the testcase at the given idx
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), Error>;

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error>;

    /// Get by id
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error>;

    /// Current testcase scheduled
    fn current(&self) -> &Option<usize>;

    /// Current testcase scheduled (mutable)
    fn current_mut(&mut self) -> &mut Option<usize>;
}

/// `Corpus` Python bindings
#[cfg(feature = "python")]
pub mod pybind {
    use crate::corpus::inmemory::pybind::PythonInMemoryCorpus;
    use crate::corpus::{Corpus, Testcase};
    use crate::inputs::BytesInput;
    use crate::Error;
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};
    use std::cell::RefCell;

    use super::cached::pybind::PythonCachedOnDiskCorpus;
    use super::ondisk::pybind::PythonOnDiskCorpus;

    #[derive(Serialize, Deserialize, Debug, Clone)]
    enum PythonCorpusWrapper {
        InMemory(PythonInMemoryCorpus),
        CachedOnDisk(PythonCachedOnDiskCorpus),
        OnDisk(PythonOnDiskCorpus),
    }

    /// Corpus Trait binding
    #[pyclass(unsendable, name = "Corpus")]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PythonCorpus {
        corpus: PythonCorpusWrapper,
    }

    #[pymethods]
    impl PythonCorpus {
        #[staticmethod]
        fn new_from_in_memory(py_in_memory_corpus: PythonInMemoryCorpus) -> Self {
            Self {
                corpus: PythonCorpusWrapper::InMemory(py_in_memory_corpus),
            }
        }

        #[staticmethod]
        fn new_from_cached_on_disk(py_cached_on_disk_corpus: PythonCachedOnDiskCorpus) -> Self {
            Self {
                corpus: PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus),
            }
        }

        #[staticmethod]
        fn new_from_on_disk(py_on_disk_corpus: PythonOnDiskCorpus) -> Self {
            Self {
                corpus: PythonCorpusWrapper::OnDisk(py_on_disk_corpus),
            }
        }
    }

    impl Corpus<BytesInput> for PythonCorpus {
        #[inline]
        fn count(&self) -> usize {
            match &self.corpus {
                PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
                    py_in_memory_corpus.in_memory_corpus.count()
                }
                PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
                    py_cached_on_disk_corpus.cached_on_disk_corpus.count()
                }
                PythonCorpusWrapper::OnDisk(py_on_disk_corpus) => {
                    py_on_disk_corpus.on_disk_corpus.count()
                }
            }
        }

        #[inline]
        fn add(&mut self, testcase: Testcase<BytesInput>) -> Result<usize, Error> {
            match &mut self.corpus {
                PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
                    py_in_memory_corpus.in_memory_corpus.add(testcase)
                }
                PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
                    py_cached_on_disk_corpus.cached_on_disk_corpus.add(testcase)
                }
                PythonCorpusWrapper::OnDisk(py_on_disk_corpus) => {
                    py_on_disk_corpus.on_disk_corpus.add(testcase)
                }
            }
        }

        #[inline]
        fn replace(&mut self, idx: usize, testcase: Testcase<BytesInput>) -> Result<(), Error> {
            match &mut self.corpus {
                PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
                    py_in_memory_corpus.in_memory_corpus.replace(idx, testcase)
                }
                PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
                    py_cached_on_disk_corpus
                        .cached_on_disk_corpus
                        .replace(idx, testcase)
                }
                PythonCorpusWrapper::OnDisk(py_on_disk_corpus) => {
                    py_on_disk_corpus.on_disk_corpus.replace(idx, testcase)
                }
            }
        }

        #[inline]
        fn remove(&mut self, idx: usize) -> Result<Option<Testcase<BytesInput>>, Error> {
            match &mut self.corpus {
                PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
                    py_in_memory_corpus.in_memory_corpus.remove(idx)
                }
                PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
                    py_cached_on_disk_corpus.cached_on_disk_corpus.remove(idx)
                }
                PythonCorpusWrapper::OnDisk(py_on_disk_corpus) => {
                    py_on_disk_corpus.on_disk_corpus.remove(idx)
                }
            }
        }

        #[inline]
        fn get(&self, idx: usize) -> Result<&RefCell<Testcase<BytesInput>>, Error> {
            match &self.corpus {
                PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
                    py_in_memory_corpus.in_memory_corpus.get(idx)
                }
                PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
                    py_cached_on_disk_corpus.cached_on_disk_corpus.get(idx)
                }
                PythonCorpusWrapper::OnDisk(py_on_disk_corpus) => {
                    py_on_disk_corpus.on_disk_corpus.get(idx)
                }
            }
        }

        #[inline]
        fn current(&self) -> &Option<usize> {
            match &self.corpus {
                PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
                    py_in_memory_corpus.in_memory_corpus.current()
                }
                PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
                    py_cached_on_disk_corpus.cached_on_disk_corpus.current()
                }
                PythonCorpusWrapper::OnDisk(py_on_disk_corpus) => {
                    py_on_disk_corpus.on_disk_corpus.current()
                }
            }
        }

        #[inline]
        fn current_mut(&mut self) -> &mut Option<usize> {
            match &mut self.corpus {
                PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
                    py_in_memory_corpus.in_memory_corpus.current_mut()
                }
                PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
                    py_cached_on_disk_corpus.cached_on_disk_corpus.current_mut()
                }
                PythonCorpusWrapper::OnDisk(py_on_disk_corpus) => {
                    py_on_disk_corpus.on_disk_corpus.current_mut()
                }
            }
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonCorpus>()?;
        Ok(())
    }
}
