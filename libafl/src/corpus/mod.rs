//! Corpuses contain the testcases, either in memory, on disk, or somewhere else.

pub mod testcase;
use serde::{Deserialize, Serialize};
pub use testcase::{SchedulerTestcaseMetaData, Testcase};

pub mod id_manager;
pub use id_manager::{CorpusID, CorpusIDManager};

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
pub trait Corpus<I>: Serialize + for<'de> Deserialize<'de>
where
    I: Input,
{
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.id_manager().active_ids().len()
    }

    /// Returns a slice of all currently active [`CorpusID`]s.
    fn ids(&self) -> &[CorpusID] {
        self.id_manager().active_ids()
    }

    /// Returns an immutable reference to the [`CorpusIDManager`]. This should be used to manage the traversal of the
    /// corpus, e.g. in a Scheduler.
    fn id_manager(&self) -> &CorpusIDManager;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Add an entry to the corpus and return its index
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusID, Error>;

    /// Replaces the testcase at the given idx
    fn replace(&mut self, idx: CorpusID, testcase: Testcase<I>) -> Result<(), Error>;

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, idx: CorpusID) -> Result<Option<Testcase<I>>, Error>;

    /// Get by id
    fn get(&self, idx: CorpusID) -> Result<&RefCell<Testcase<I>>, Error>;

    /// Current testcase scheduled
    fn current(&self) -> &Option<CorpusID>;

    /// Current testcase scheduled (mutable)
    fn current_mut(&mut self) -> &mut Option<CorpusID>;
}

/// `Corpus` Python bindings
#[cfg(feature = "python")]
#[allow(missing_docs)]
pub mod pybind {
    use crate::corpus::inmemory::pybind::PythonInMemoryCorpus;
    use crate::corpus::testcase::pybind::PythonTestcaseWrapper;
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

    impl Corpus<BytesInput> for PythonCorpus {
        #[inline]
        fn count(&self) -> usize {
            unwrap_me!(self.wrapper, c, { c.count() })
        }

        #[inline]
        fn add(&mut self, testcase: Testcase<BytesInput>) -> Result<usize, Error> {
            unwrap_me_mut!(self.wrapper, c, { c.add(testcase) })
        }

        #[inline]
        fn replace(&mut self, idx: usize, testcase: Testcase<BytesInput>) -> Result<(), Error> {
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
