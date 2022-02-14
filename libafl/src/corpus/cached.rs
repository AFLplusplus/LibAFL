//! The cached ondisk corpus stores testcases to disk keeping a part of them in memory.

use alloc::collections::vec_deque::VecDeque;
use core::cell::RefCell;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    corpus::{
        ondisk::{OnDiskCorpus, OnDiskMetadataFormat},
        Corpus, Testcase,
    },
    inputs::Input,
    Error,
};

/// A corpus that keep in memory a maximun number of testcases. The eviction policy is FIFO.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct CachedOnDiskCorpus<I>
where
    I: Input,
{
    inner: OnDiskCorpus<I>,
    cached_indexes: RefCell<VecDeque<usize>>,
    cache_max_len: usize,
}

impl<I> Corpus<I> for CachedOnDiskCorpus<I>
where
    I: Input,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.inner.count()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<usize, Error> {
        self.inner.add(testcase)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), Error> {
        // TODO finish
        self.inner.replace(idx, testcase)
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error> {
        let testcase = self.inner.remove(idx)?;
        if testcase.is_some() {
            self.cached_indexes.borrow_mut().retain(|e| *e != idx);
        }
        Ok(testcase)
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error> {
        let testcase = { self.inner.get(idx)? };
        if testcase.borrow().input().is_none() {
            let _ = testcase.borrow_mut().load_input()?;
            let mut borrowed_num = 0;
            while self.cached_indexes.borrow().len() >= self.cache_max_len {
                let removed = self.cached_indexes.borrow_mut().pop_front().unwrap();
                if let Ok(mut borrowed) = self.inner.get(removed)?.try_borrow_mut() {
                    *borrowed.input_mut() = None;
                } else {
                    self.cached_indexes.borrow_mut().push_back(removed);
                    borrowed_num += 1;
                    if self.cache_max_len == borrowed_num {
                        break;
                    }
                }
            }
            self.cached_indexes.borrow_mut().push_back(idx);
        }
        Ok(testcase)
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<usize> {
        self.inner.current()
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<usize> {
        self.inner.current_mut()
    }
}

impl<I> CachedOnDiskCorpus<I>
where
    I: Input,
{
    /// Creates the [`CachedOnDiskCorpus`].
    pub fn new(dir_path: PathBuf, cache_max_len: usize) -> Result<Self, Error> {
        if cache_max_len == 0 {
            return Err(Error::IllegalArgument(
                "The max cache len in CachedOnDiskCorpus cannot be 0".into(),
            ));
        }
        Ok(Self {
            inner: OnDiskCorpus::new(dir_path)?,
            cached_indexes: RefCell::new(VecDeque::new()),
            cache_max_len,
        })
    }

    /// Creates the [`CachedOnDiskCorpus`] specifying the type of `Metadata` to be saved to disk.
    pub fn new_save_meta(
        dir_path: PathBuf,
        meta_format: Option<OnDiskMetadataFormat>,
        cache_max_len: usize,
    ) -> Result<Self, Error> {
        if cache_max_len == 0 {
            return Err(Error::IllegalArgument(
                "The max cache len in CachedOnDiskCorpus cannot be 0".into(),
            ));
        }
        Ok(Self {
            inner: OnDiskCorpus::new_save_meta(dir_path, meta_format)?,
            cached_indexes: RefCell::new(VecDeque::new()),
            cache_max_len,
        })
    }
}

/// ``CachedOnDiskCorpus`` Python bindings
#[cfg(feature = "python")]
pub mod pybind {
    use std::path::PathBuf;

    use crate::corpus::CachedOnDiskCorpus;
    use crate::inputs::BytesInput;
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    #[pyclass(unsendable, name = "CachedOnDiskCorpus")]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    /// Python class for CachedOnDiskCorpus
    pub struct PythonCachedOnDiskCorpus {
        /// Rust wrapped CachedOnDiskCorpus object
        pub cached_on_disk_corpus: CachedOnDiskCorpus<BytesInput>,
    }

    #[pymethods]
    impl PythonCachedOnDiskCorpus {
        #[new]
        fn new(path: String, cache_max_len: usize) -> Self {
            Self {
                cached_on_disk_corpus: CachedOnDiskCorpus::new(PathBuf::from(path), cache_max_len)
                    .unwrap(),
            }
        }
    }
    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonCachedOnDiskCorpus>()?;
        Ok(())
    }
}
