//! The ondisk corpus stores all [`Testcase`]s to disk.
//! It never keeps any of them in memory.
//! This is a good solution for solutions that are never reused, and for very memory-constraint environments.
//! For any other occasions, consider using [`crate::corpus::CachedOnDiskCorpus`]
//! which stores a certain number of testcases in memory and removes additional ones in a FIFO manner.

use alloc::string::String;
use core::{cell::RefCell, time::Duration};
use std::path::{Path, PathBuf};

use libafl_bolts::serdeany::SerdeAnyMap;
use serde::{Deserialize, Serialize};

use super::{CachedOnDiskCorpus, HasTestcase};
use crate::{
    corpus::{Corpus, CorpusId, Testcase},
    inputs::{Input, UsesInput},
    Error,
};

/// Options for the the format of the on-disk metadata
#[cfg(feature = "std")]
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum OnDiskMetadataFormat {
    /// A binary-encoded postcard
    Postcard,
    /// JSON
    Json,
    /// JSON formatted for readability
    #[default]
    JsonPretty,
    /// The same as [`OnDiskMetadataFormat::JsonPretty`], but compressed
    #[cfg(feature = "gzip")]
    JsonGzip,
}

/// The [`Testcase`] metadata that'll be stored to disk
#[derive(Debug, Serialize)]
pub struct OnDiskMetadata<'a> {
    /// The dynamic metadata [`SerdeAnyMap`] stored to disk
    pub metadata: &'a SerdeAnyMap,
    /// The exec time for this [`Testcase`]
    pub exec_time: &'a Option<Duration>,
    /// The amount of executions for this [`Testcase`]
    pub executions: &'a u64,
}

/// A corpus able to store [`Testcase`]s to disk, and load them from disk, when they are being used.
///
/// Metadata is written to a `.<filename>.metadata` file in the same folder by default.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct OnDiskCorpus<I>
where
    I: Input,
{
    /// The root directory backing this corpus
    dir_path: PathBuf,
    /// We wrapp a cached corpus and set its size to 1.
    inner: CachedOnDiskCorpus<I>,
}

impl<I> UsesInput for OnDiskCorpus<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> Corpus for OnDiskCorpus<I>
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
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        self.inner.add(testcase)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        self.inner.replace(idx, testcase)
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: CorpusId) -> Result<Testcase<I>, Error> {
        self.inner.remove(idx)
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        self.inner.get(idx)
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        self.inner.current()
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        self.inner.current_mut()
    }

    #[inline]
    fn next(&self, idx: CorpusId) -> Option<CorpusId> {
        self.inner.next(idx)
    }

    #[inline]
    fn prev(&self, idx: CorpusId) -> Option<CorpusId> {
        self.inner.prev(idx)
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        self.inner.first()
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        self.inner.last()
    }

    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        self.inner.nth(nth)
    }

    #[inline]
    fn load_input_into(&self, testcase: &mut Testcase<Self::Input>) -> Result<(), Error> {
        self.inner.load_input_into(testcase)
    }

    #[inline]
    fn store_input_from(&self, testcase: &Testcase<Self::Input>) -> Result<(), Error> {
        self.inner.store_input_from(testcase)
    }
}

impl<I> HasTestcase for OnDiskCorpus<I>
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

impl<I> OnDiskCorpus<I>
where
    I: Input,
{
    /// Creates an [`OnDiskCorpus`].
    ///
    /// This corpus stores all testcases to disk.
    ///
    /// By default, it stores metadata for each [`Testcase`] as prettified json.
    /// Metadata will be written to a file named `.<testcase>.metadata`
    /// The metadata may include objective reason, specific information for a fuzz job, and more.
    ///
    /// To pick a different metadata format, use [`OnDiskCorpus::with_meta_format`].
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::with_meta_format_and_prefix(
            dir_path.as_ref(),
            Some(OnDiskMetadataFormat::JsonPretty),
            None,
            true,
        )
    }

    /// Creates the [`OnDiskCorpus`] with a filename prefix.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_prefix<P>(dir_path: P, prefix: Option<String>) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::with_meta_format_and_prefix(
            dir_path.as_ref(),
            Some(OnDiskMetadataFormat::JsonPretty),
            prefix,
            true,
        )
    }

    /// Creates the [`OnDiskCorpus`] specifying the format in which `Metadata` will be saved to disk.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format<P>(
        dir_path: P,
        meta_format: OnDiskMetadataFormat,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::with_meta_format_and_prefix(dir_path.as_ref(), Some(meta_format), None, true)
    }

    /// Creates an [`OnDiskCorpus`] that will not store .metadata files
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn no_meta<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::with_meta_format_and_prefix(dir_path.as_ref(), None, None, true)
    }

    /// Creates a new corpus at the given (non-generic) path with the given optional `meta_format`
    /// and `prefix`.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format_and_prefix(
        dir_path: &Path,
        meta_format: Option<OnDiskMetadataFormat>,
        prefix: Option<String>,
        locking: bool,
    ) -> Result<Self, Error> {
        Ok(OnDiskCorpus {
            dir_path: dir_path.into(),
            inner: CachedOnDiskCorpus::with_meta_format_and_prefix(
                dir_path,
                1,
                meta_format,
                prefix,
                locking,
            )?,
        })
    }

    /// Path to the corpus directory associated with this corpus
    pub fn dir_path(&self) -> &PathBuf {
        &self.dir_path
    }
}

#[cfg(feature = "python")]
#[allow(clippy::unnecessary_fallible_conversions, unused_qualifications)]
/// `OnDiskCorpus` Python bindings
pub mod pybind {
    use alloc::string::String;
    use std::path::PathBuf;

    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    use crate::{
        corpus::{pybind::PythonCorpus, OnDiskCorpus},
        inputs::BytesInput,
    };

    #[pyclass(unsendable, name = "OnDiskCorpus")]
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    /// Python class for OnDiskCorpus
    pub struct PythonOnDiskCorpus {
        /// Rust wrapped OnDiskCorpus object
        pub inner: OnDiskCorpus<BytesInput>,
    }

    #[pymethods]
    impl PythonOnDiskCorpus {
        #[new]
        fn new(path: String) -> Self {
            Self {
                inner: OnDiskCorpus::new(PathBuf::from(path)).unwrap(),
            }
        }

        fn as_corpus(slf: Py<Self>) -> PythonCorpus {
            PythonCorpus::new_on_disk(slf)
        }
    }
    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonOnDiskCorpus>()?;
        Ok(())
    }
}
