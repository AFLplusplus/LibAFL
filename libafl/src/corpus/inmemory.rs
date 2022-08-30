//! In-memory corpus, keeps all test cases in memory at all times

use alloc::vec::Vec;
use core::cell::RefCell;

use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, Testcase},
    Error,
};

/// A corpus handling all in memory.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "<Self as Corpus>::Input: serde::de::DeserializeOwned")]
pub struct InMemoryCorpus {
    entries: Vec<RefCell<Testcase<<Self as Corpus>::Input>>>,
    current: Option<usize>,
}

impl Corpus for InMemoryCorpus {
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.entries.len()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<Self::Input>) -> Result<usize, Error> {
        self.entries.push(RefCell::new(testcase));
        Ok(self.entries.len() - 1)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(
        &mut self,
        idx: usize,
        testcase: Testcase<Self::Input>,
    ) -> Result<Testcase<Self::Input>, Error> {
        if idx >= self.entries.len() {
            return Err(Error::key_not_found(format!("Index {} out of bounds", idx)));
        }
        Ok(self.entries[idx].replace(testcase))
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<Self::Input>>, Error> {
        if idx >= self.entries.len() {
            Ok(None)
        } else {
            Ok(Some(self.entries.remove(idx).into_inner()))
        }
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<Self::Input>>, Error> {
        Ok(&self.entries[idx])
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<usize> {
        &self.current
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<usize> {
        &mut self.current
    }
}

impl InMemoryCorpus {
    /// Creates a new [`InMemoryCorpus`], keeping all [`Testcase`]`s` in memory.
    /// This is the simplest and fastest option, however test progress will be lost on exit or on OOM.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: vec![],
            current: None,
        }
    }
}

/// `InMemoryCorpus` Python bindings
#[cfg(feature = "python")]
pub mod pybind {
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    use crate::{
        corpus::{pybind::PythonCorpus, InMemoryCorpus},
        inputs::BytesInput,
    };

    #[pyclass(unsendable, name = "InMemoryCorpus")]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    /// Python class for InMemoryCorpus
    pub struct PythonInMemoryCorpus {
        /// Rust wrapped InMemoryCorpus object
        pub inner: InMemoryCorpus<Input = BytesInput>,
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
