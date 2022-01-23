//! Corpuses contain the testcases, either in mem, on disk, or somewhere else.

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

pub mod queue;
pub use queue::QueueCorpusScheduler;

pub mod minimizer;
pub use minimizer::{
    FavFactor, IndexesLenTimeMinimizerCorpusScheduler, IsFavoredMetadata,
    LenTimeMinimizerCorpusScheduler, LenTimeMulFavFactor, MinimizerCorpusScheduler,
    TopRatedsMetadata,
};

pub mod powersched;
pub use powersched::PowerQueueCorpusScheduler;

use alloc::borrow::ToOwned;
use core::cell::RefCell;

use crate::{
    bolts::rands::Rand,
    inputs::Input,
    state::{HasCorpus, HasRand},
    Error,
};

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

    /// Current testcase scheduled (mut)
    fn current_mut(&mut self) -> &mut Option<usize>;
}

/// The scheduler define how the fuzzer requests a testcase from the corpus.
/// It has hooks to corpus add/replace/remove to allow complex scheduling algorithms to collect data.
pub trait CorpusScheduler<I, S>
where
    I: Input,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, _state: &mut S, _idx: usize) -> Result<(), Error> {
        Ok(())
    }

    /// Replaces the testcase at the given idx
    fn on_replace(
        &self,
        _state: &mut S,
        _idx: usize,
        _testcase: &Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn on_remove(
        &self,
        _state: &mut S,
        _idx: usize,
        _testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Gets the next entry
    fn next(&self, state: &mut S) -> Result<usize, Error>;
}

/// Feed the fuzzer simpply with a random testcase on request
#[derive(Debug, Clone)]
pub struct RandCorpusScheduler;

impl<I, S> CorpusScheduler<I, S> for RandCorpusScheduler
where
    S: HasCorpus<I> + HasRand,
    I: Input,
{
    /// Gets the next entry at random
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty("No entries in corpus".to_owned()))
        } else {
            let len = state.corpus().count();
            let id = state.rand_mut().below(len as u64) as usize;
            *state.corpus_mut().current_mut() = Some(id);
            Ok(id)
        }
    }
}

impl RandCorpusScheduler {
    /// Create a new [`RandCorpusScheduler`] that just schedules randomly.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RandCorpusScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`StdCorpusScheduler`] uses the default scheduler in `LibAFL` to schedule [`Testcase`]s
/// The current `Std` is a [`RandCorpusScheduler`], although this may change in the future, if another [`CorpusScheduler`] delivers better results.
pub type StdCorpusScheduler = RandCorpusScheduler;

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

    // impl PythonCorpus {
    //     fn get_corpus(&self) -> &impl Corpus<BytesInput> {
    //         match &self.corpus {
    //             PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
    //                 &py_in_memory_corpus.in_memory_corpus
    //             },
    //             PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
    //                 &py_cached_on_disk_corpus.cached_on_disk_corpus
    //             }
    //         }
    //     }

    //     fn get_mut_corpus(&mut self) -> &mut impl Corpus<BytesInput> {
    //         match &mut self.corpus {
    //             PythonCorpusWrapper::InMemory(py_in_memory_corpus) => {
    //                 &mut py_in_memory_corpus.in_memory_corpus
    //             },
    //             PythonCorpusWrapper::CachedOnDisk(py_cached_on_disk_corpus) => {
    //                 &mut py_cached_on_disk_corpus.cached_on_disk_corpus
    //             },
    //         }
    //     }
    // }

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
