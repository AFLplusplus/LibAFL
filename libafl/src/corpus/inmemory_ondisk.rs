//! The [`InMemoryOnDiskCorpus`] stores [`Testcase`]s to disk.
//! Additionally, _all_ of them are kept in memory.
//! For a lower memory footprint, consider using [`crate::corpus::CachedOnDiskCorpus`]
//! which only stores a certain number of [`Testcase`]s and removes additional ones in a FIFO manner.

use alloc::string::String;
use core::{cell::RefCell, time::Duration};
#[cfg(feature = "std")]
use std::{fs, fs::File, io::Write};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

#[cfg(feature = "gzip")]
use libafl_bolts::compress::GzipCompressor;
use libafl_bolts::serdeany::SerdeAnyMap;
use serde::{Deserialize, Serialize};

use super::{
    ondisk::{OnDiskMetadata, OnDiskMetadataFormat},
    HasTestcase,
};
use crate::{
    corpus::{Corpus, CorpusId, InMemoryCorpus, Testcase},
    inputs::{Input, UsesInput},
    state::HasMetadata,
    Error,
};

/// The [`Testcase`] metadata that'll be stored to disk
#[cfg(feature = "std")]
#[derive(Debug, Serialize)]
pub struct InMemoryOnDiskMetadata<'a> {
    metadata: &'a SerdeAnyMap,
    exec_time: &'a Option<Duration>,
    executions: &'a usize,
}

/// A corpus able to store [`Testcase`]s to disk, while also keeping all of them in memory.
///
/// Metadata is written to a `.<filename>.metadata` file in the same folder by default.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct InMemoryOnDiskCorpus<I>
where
    I: Input,
{
    inner: InMemoryCorpus<I>,
    dir_path: PathBuf,
    meta_format: Option<OnDiskMetadataFormat>,
    prefix: Option<String>,
    locking: bool,
}

impl<I> UsesInput for InMemoryOnDiskCorpus<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> Corpus for InMemoryOnDiskCorpus<I>
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
        let testcase = &mut self.get(idx).unwrap().borrow_mut();
        self.save_testcase(testcase, idx)?;
        *testcase.input_mut() = None;
        Ok(idx)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        let entry = self.inner.replace(idx, testcase)?;
        self.remove_testcase(&entry)?;
        let testcase = &mut self.get(idx).unwrap().borrow_mut();
        self.save_testcase(testcase, idx)?;
        *testcase.input_mut() = None;
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

    fn load_input_into(&self, testcase: &mut Testcase<Self::Input>) -> Result<(), Error> {
        if testcase.input_mut().is_none() {
            let Some(file_path) = testcase.file_path().as_ref() else {
                return Err(Error::illegal_argument(
                    "No file path set for testcase. Could not load inputs.",
                ));
            };
            let input = I::from_file(file_path)?;
            testcase.set_input(input);
        }
        Ok(())
    }

    fn store_input_from(&self, testcase: &Testcase<Self::Input>) -> Result<(), Error> {
        // Store the input to disk
        let Some(file_path) = testcase.file_path() else {
            return Err(Error::illegal_argument(
                "No file path set for testcase. Could not store input to disk.",
            ));
        };
        let Some(input) = testcase.input() else {
            return Err(Error::illegal_argument(
                "No input available for testcase. Could not store anything.",
            ));
        };
        input.to_file(file_path)
    }
}

impl<I> HasTestcase for InMemoryOnDiskCorpus<I>
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

impl<I> InMemoryOnDiskCorpus<I>
where
    I: Input,
{
    /// Creates an [`InMemoryOnDiskCorpus`].
    ///
    /// This corpus stores all testcases to disk, and keeps all of them in memory, as well.
    ///
    /// By default, it stores metadata for each [`Testcase`] as prettified json.
    /// Metadata will be written to a file named `.<testcase>.metadata`
    /// The metadata may include objective reason, specific information for a fuzz job, and more.
    ///
    /// If you don't want metadata, use [`InMemoryOnDiskCorpus::no_meta`].
    /// To pick a different metadata format, use [`InMemoryOnDiskCorpus::with_meta_format`].
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(
            dir_path.as_ref(),
            Some(OnDiskMetadataFormat::JsonPretty),
            None,
            true,
        )
    }

    /// Creates the [`InMemoryOnDiskCorpus`] specifying the format in which `Metadata` will be saved to disk.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format<P>(
        dir_path: P,
        meta_format: Option<OnDiskMetadataFormat>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(dir_path.as_ref(), meta_format, None, true)
    }

    /// Creates the [`InMemoryOnDiskCorpus`] specifying the format in which `Metadata` will be saved to disk
    /// and the prefix for the filenames.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format_and_prefix<P>(
        dir_path: P,
        meta_format: Option<OnDiskMetadataFormat>,
        prefix: Option<String>,
        locking: bool,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(dir_path.as_ref(), meta_format, prefix, locking)
    }

    /// Creates an [`InMemoryOnDiskCorpus`] that will not store .metadata files
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn no_meta<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(dir_path.as_ref(), None, None, true)
    }

    /// Private fn to crate a new corpus at the given (non-generic) path with the given optional `meta_format`
    fn _new(
        dir_path: &Path,
        meta_format: Option<OnDiskMetadataFormat>,
        prefix: Option<String>,
        locking: bool,
    ) -> Result<Self, Error> {
        match fs::create_dir_all(dir_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        Ok(InMemoryOnDiskCorpus {
            inner: InMemoryCorpus::new(),
            dir_path: dir_path.into(),
            meta_format,
            prefix,
            locking,
        })
    }

    /// Sets the filename for a [`Testcase`].
    /// If an error gets returned from the corpus (i.e., file exists), we'll have to retry with a different filename.
    #[inline]
    pub fn rename_testcase(
        &self,
        testcase: &mut Testcase<I>,
        filename: String,
    ) -> Result<(), Error> {
        if testcase.filename().is_some() {
            // We are renaming!

            let old_filename = testcase.filename_mut().take().unwrap();
            let new_filename = filename;

            // Do operations below when new filename is specified
            if old_filename == new_filename {
                *testcase.filename_mut() = Some(old_filename);
                return Ok(());
            }

            if self.locking {
                let new_lock_filename = format!(".{new_filename}.lafl_lock");

                // Try to create lock file for new testcases
                if OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(self.dir_path.join(new_lock_filename))
                    .is_err()
                {
                    *testcase.filename_mut() = Some(old_filename);
                    return Err(Error::illegal_state(
                        "unable to create lock file for new testcase",
                    ));
                }
            }

            let new_file_path = self.dir_path.join(&new_filename);

            fs::rename(testcase.file_path().as_ref().unwrap(), &new_file_path)?;

            let new_metadata_path = {
                if let Some(old_metadata_path) = testcase.metadata_path() {
                    // We have metadata. Let's rename it.
                    let new_metadata_path = self.dir_path.join(format!(".{new_filename}.metadata"));
                    fs::rename(old_metadata_path, &new_metadata_path)?;

                    Some(new_metadata_path)
                } else {
                    None
                }
            };

            *testcase.metadata_path_mut() = new_metadata_path;
            *testcase.filename_mut() = Some(new_filename);
            *testcase.file_path_mut() = Some(new_file_path);

            Ok(())
        } else {
            Err(Error::illegal_argument(
                "Cannot rename testcase without name!",
            ))
        }
    }

    fn save_testcase(&self, testcase: &mut Testcase<I>, idx: CorpusId) -> Result<(), Error> {
        let file_name_orig = testcase.filename_mut().take().unwrap_or_else(|| {
            // TODO walk entry metadata to ask for pieces of filename (e.g. :havoc in AFL)
            testcase.input().as_ref().unwrap().generate_name(idx.0)
        });

        // New testcase, we need to save it.
        let mut file_name = file_name_orig.clone();

        let mut ctr = 2;
        let file_name = if self.locking {
            loop {
                let lockfile_name = format!(".{file_name}.lafl_lock");
                let lockfile_path = self.dir_path.join(lockfile_name);

                if OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(lockfile_path)
                    .is_ok()
                {
                    break file_name;
                }

                file_name = format!("{file_name_orig}-{ctr}");
                ctr += 1;
            }
        } else {
            file_name
        };

        if testcase
            .file_path()
            .as_ref()
            .map_or(true, |path| !path.starts_with(&self.dir_path))
        {
            *testcase.file_path_mut() = Some(self.dir_path.join(&file_name));
        }
        *testcase.filename_mut() = Some(file_name);

        if self.meta_format.is_some() {
            let metafile_name = format!(".{}.metadata", testcase.filename().as_ref().unwrap());
            let metafile_path = self.dir_path.join(&metafile_name);
            let mut tmpfile_path = metafile_path.clone();
            tmpfile_path.set_file_name(format!(".{metafile_name}.tmp",));

            let ondisk_meta = OnDiskMetadata {
                metadata: testcase.metadata_map(),
                exec_time: testcase.exec_time(),
                executions: testcase.executions(),
            };

            let mut tmpfile = File::create(&tmpfile_path)?;

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
            fs::rename(&tmpfile_path, &metafile_path)?;
            *testcase.metadata_path_mut() = Some(metafile_path);
        }

        self.store_input_from(testcase)?;
        Ok(())
    }

    fn remove_testcase(&self, testcase: &Testcase<I>) -> Result<(), Error> {
        if let Some(filename) = testcase.filename() {
            fs::remove_file(self.dir_path.join(filename))?;
            if self.meta_format.is_some() {
                fs::remove_file(self.dir_path.join(format!(".{filename}.metadata")))?;
            }
            // also try to remove the corresponding `.lafl_lock` file if it still exists
            // (even though it shouldn't exist anymore, at this point in time)
            drop(fs::remove_file(
                self.dir_path.join(format!(".{filename}.lafl_lock")),
            ));
        }
        Ok(())
    }

    /// Path to the corpus directory associated with this corpus
    #[must_use]
    pub fn dir_path(&self) -> &PathBuf {
        &self.dir_path
    }
}

#[cfg(feature = "python")]
#[allow(clippy::unnecessary_fallible_conversions, unused_qualifications)]
/// `InMemoryOnDiskCorpus` Python bindings
pub mod pybind {
    use alloc::string::String;
    use std::path::PathBuf;

    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    use crate::{
        corpus::{pybind::PythonCorpus, InMemoryOnDiskCorpus},
        inputs::BytesInput,
    };

    #[pyclass(unsendable, name = "InMemoryOnDiskCorpus")]
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    /// Python class for InMemoryOnDiskCorpus
    pub struct PythonInMemoryOnDiskCorpus {
        /// Rust wrapped InMemoryOnDiskCorpus object
        pub inner: InMemoryOnDiskCorpus<BytesInput>,
    }

    #[pymethods]
    impl PythonInMemoryOnDiskCorpus {
        #[new]
        fn new(path: String) -> Self {
            Self {
                inner: InMemoryOnDiskCorpus::new(PathBuf::from(path)).unwrap(),
            }
        }

        fn as_corpus(slf: Py<Self>) -> PythonCorpus {
            PythonCorpus::new_in_memory_on_disk(slf)
        }
    }
    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonInMemoryOnDiskCorpus>()?;
        Ok(())
    }
}
