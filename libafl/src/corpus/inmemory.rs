//! In-memory corpus, keeps all test cases in memory at all times

use alloc::vec::Vec;
use core::cell::RefCell;

use serde::{Deserialize, Serialize};

use super::{id_manager::CorpusIdManager, CorpusId};
use crate::{
    corpus::{Corpus, Testcase},
    inputs::{Input, UsesInput},
    Error,
};

/// A corpus handling all in memory.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct InMemoryCorpus<I>
where
    I: Input,
{
    entries: Vec<RefCell<Testcase<I>>>,
    current: Option<CorpusId>,
    id_manager: CorpusIdManager,
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
        self.entries.len()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        debug_assert!(self.entries.len() == self.id_manager.active_ids().len());
        let new_id = self.id_manager.provide_next();
        self.entries.push(RefCell::new(testcase));
        Ok(new_id)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        let old_idx = self
            .id_manager
            .remove_id(idx)
            .ok_or_else(|| Error::key_not_found(format!("ID {idx:?} is stale")))?;
        Ok(self.entries[old_idx].replace(testcase))
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, id: CorpusId) -> Result<Option<Testcase<I>>, Error> {
        if let Some(old_idx) = self.id_manager.remove_id(id) {
            Ok(Some(self.entries.remove(old_idx).into_inner()))
        } else {
            Ok(None)
        }
    }

    /// Get by id
    #[inline]
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        let idx = self
            .id_manager
            .active_index_for(id)
            .ok_or_else(|| Error::key_not_found(format!("ID {id:?} is stale")))?;
        Ok(&self.entries[idx])
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

    fn id_manager(&self) -> &CorpusIdManager {
        &self.id_manager
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
            entries: vec![],
            current: None,
            id_manager: CorpusIdManager::new(),
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
