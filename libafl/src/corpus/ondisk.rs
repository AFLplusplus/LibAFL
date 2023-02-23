//! The ondisk corpus stores [`Testcase`]s to disk.
//! Additionally, all of them are kept in memory.
//! For a lower memory footprint, consider using [`crate::corpus::CachedOnDiskCorpus`]
//! which only stores a certain number of testcases and removes additional ones in a FIFO manner.

use core::{cell::RefCell, time::Duration};
#[cfg(feature = "std")]
use std::{fs, fs::File, io::Write};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[cfg(feature = "gzip")]
use crate::bolts::compress::GzipCompressor;
use crate::{
    bolts::serdeany::SerdeAnyMap,
    corpus::{Corpus, CorpusId, InMemoryCorpus, Testcase},
    inputs::{Input, UsesInput},
    state::HasMetadata,
    Error,
};

/// Options for the the format of the on-disk metadata
#[cfg(feature = "std")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OnDiskMetadataFormat {
    /// A binary-encoded postcard
    Postcard,
    /// JSON
    Json,
    /// JSON formatted for readability
    JsonPretty,
    #[cfg(feature = "gzip")]
    /// The same as [`OnDiskMetadataFormat::JsonPretty`], but compressed
    JsonGzip,
}

/// The [`Testcase`] metadata that'll be stored to disk
#[cfg(feature = "std")]
#[derive(Debug, Serialize)]
pub struct OnDiskMetadata<'a> {
    metadata: &'a SerdeAnyMap,
    exec_time: &'a Option<Duration>,
    executions: &'a usize,
}

/// A corpus able to store [`Testcase`]s to disk, and load them from disk, when they are being used.
///
/// Metadata is written to a `.<filename>.metadata` file in the same folder by default.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct OnDiskCorpus<I>
where
    I: Input,
{
    inner: InMemoryCorpus<I>,
    dir_path: PathBuf,
    meta_format: Option<OnDiskMetadataFormat>,
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
        let idx = self.inner.add(testcase)?;
        self.save_testcase(&mut self.get(idx).unwrap().borrow_mut(), idx)?;
        Ok(idx)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        let entry = self.inner.replace(idx, testcase)?;
        self.remove_testcase(&entry)?;
        self.save_testcase(&mut self.get(idx).unwrap().borrow_mut(), idx)?;
        Ok(entry)
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: CorpusId) -> Result<Testcase<I>, Error> {
        let entry = self.inner.remove(idx)?;
        self.remove_testcase(&entry)?;
        Ok(entry)
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
}

impl<I> OnDiskCorpus<I>
where
    I: Input,
{
    /// Creates an [`OnDiskCorpus`].
    ///
    /// This corpus stores all testcases to disk, and keeps all of them in memory, as well.
    ///
    /// By default, it stores metadata for each [`Testcase`] as prettified json.
    /// Metadata will be written to a file named `.<testcase>.metadata`
    /// The metadata may include objective reason, specific information for a fuzz job, and more.
    ///
    /// If you don't want metadata, use [`OnDiskCorpus::no_meta`].
    /// To pick a different metadata format, use [`OnDiskCorpus::with_meta_format`].
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(dir_path.as_ref(), Some(OnDiskMetadataFormat::JsonPretty))
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
        Self::_new(dir_path.as_ref(), Some(meta_format))
    }

    /// Creates an [`OnDiskCorpus`] that will not store .metadata files
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn no_meta<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(dir_path.as_ref(), None)
    }

    /// Private fn to crate a new corpus at the given (non-generic) path with the given optional `meta_format`
    fn _new(dir_path: &Path, meta_format: Option<OnDiskMetadataFormat>) -> Result<Self, Error> {
        fs::create_dir_all(dir_path)?;
        Ok(OnDiskCorpus {
            inner: InMemoryCorpus::new(),
            dir_path: dir_path.into(),
            meta_format,
        })
    }

    fn save_testcase(&self, testcase: &mut Testcase<I>, idx: CorpusId) -> Result<(), Error> {
        if testcase.filename().is_none() {
            // TODO walk entry metadata to ask for pieces of filename (e.g. :havoc in AFL)
            let file_orig = testcase.input().as_ref().unwrap().generate_name(idx.0);
            let mut file = file_orig.clone();

            let mut ctr = 2;
            let filename = loop {
                let lockfile = format!(".{file}.lafl_lock");
                // try to create lockfile.

                if OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.dir_path.join(lockfile))
                    .is_ok()
                {
                    break self.dir_path.join(file);
                }

                file = format!("{file_orig}-{ctr}");
                ctr += 1;
            };

            let filename_str = filename.to_str().expect("Invalid Path");
            testcase
                .set_filename(filename_str.into())?;
        };
        if self.meta_format.is_some() {
            let mut filename = PathBuf::from(testcase.filename().as_ref().unwrap());
            filename.set_file_name(format!(
                ".{}.metadata",
                filename.file_name().unwrap().to_string_lossy()
            ));
            let mut tmpfile_name = PathBuf::from(&filename);
            tmpfile_name.set_file_name(format!(
                ".{}.tmp",
                tmpfile_name.file_name().unwrap().to_string_lossy()
            ));

            let ondisk_meta = OnDiskMetadata {
                metadata: testcase.metadata(),
                exec_time: testcase.exec_time(),
                executions: testcase.executions(),
            };

            let mut tmpfile = File::create(&tmpfile_name)?;

            let serialized = match self.meta_format.as_ref().unwrap() {
                OnDiskMetadataFormat::Postcard => postcard::to_allocvec(&ondisk_meta)?,
                OnDiskMetadataFormat::Json => serde_json::to_vec(&ondisk_meta)?,
                OnDiskMetadataFormat::JsonPretty => serde_json::to_vec_pretty(&ondisk_meta)?,
                #[cfg(feature = "gzip")]
                OnDiskMetadataFormat::JsonGzip => GzipCompressor::new(0)
                    .compress(&serde_json::to_vec_pretty(&ondisk_meta)?)?
                    .unwrap(),
            };
            tmpfile.write_all(&serialized)?;
            fs::rename(&tmpfile_name, &filename)?;
        }
        testcase
            .store_input()
            .expect("Could not save testcase to disk");
        Ok(())
    }

    fn remove_testcase(&self, testcase: &Testcase<I>) -> Result<(), Error> {
        if let Some(filename) = testcase.filename() {
            fs::remove_file(filename)?;
        }
        if self.meta_format.is_some() {
            let mut filename = PathBuf::from(testcase.filename().as_ref().unwrap());
            filename.set_file_name(format!(
                ".{}.metadata",
                filename.file_name().unwrap().to_string_lossy()
            ));
            fs::remove_file(filename)?;
        }
        Ok(())
    }
}

#[cfg(feature = "python")]
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
