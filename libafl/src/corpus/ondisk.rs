//! The ondisk corpus stores unused testcases to disk.

use alloc::vec::Vec;
use core::{cell::RefCell, time::Duration};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

#[cfg(feature = "std")]
use std::{fs, fs::File, io::Write};

use crate::{
    bolts::serdeany::SerdeAnyMap, corpus::Corpus, corpus::Testcase, inputs::Input,
    state::HasMetadata, Error,
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
}

/// A corpus able to store testcases to disk, and load them from disk, when they are being used.
#[cfg(feature = "std")]
#[derive(Debug, Serialize)]
pub struct OnDiskMetadata<'a> {
    metadata: &'a SerdeAnyMap,
    exec_time: &'a Option<Duration>,
    executions: &'a usize,
}

/// A corpus able to store testcases to disk, and load them from disk, when they are being used.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct OnDiskCorpus<I>
where
    I: Input,
{
    entries: Vec<RefCell<Testcase<I>>>,
    current: Option<usize>,
    dir_path: PathBuf,
    meta_format: Option<OnDiskMetadataFormat>,
}

impl<I> Corpus<I> for OnDiskCorpus<I>
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
    fn add(&mut self, mut testcase: Testcase<I>) -> Result<usize, Error> {
        if testcase.filename().is_none() {
            // TODO walk entry metadata to ask for pieces of filename (e.g. :havoc in AFL)
            let file_orig = testcase
                .input()
                .as_ref()
                .unwrap()
                .generate_name(self.entries.len());
            let mut file = file_orig.clone();

            let mut ctr = 2;
            let filename = loop {
                let lockfile = format!(".{}.lafl_lock", file);
                // try to create lockfile.

                if OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(self.dir_path.join(lockfile))
                    .is_ok()
                {
                    break self.dir_path.join(file);
                }

                file = format!("{}-{}", &file_orig, ctr);
                ctr += 1;
            };

            let filename_str = filename.to_str().expect("Invalid Path");
            testcase.set_filename(filename_str.into());
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
            };
            tmpfile.write_all(&serialized)?;
            fs::rename(&tmpfile_name, &filename)?;
        }
        testcase
            .store_input()
            .expect("Could not save testcase to disk");
        self.entries.push(RefCell::new(testcase));
        Ok(self.entries.len() - 1)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), Error> {
        if idx >= self.entries.len() {
            return Err(Error::KeyNotFound(format!("Index {} out of bounds", idx)));
        }
        self.entries[idx] = RefCell::new(testcase);
        Ok(())
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error> {
        if idx >= self.entries.len() {
            Ok(None)
        } else {
            Ok(Some(self.entries.remove(idx).into_inner()))
        }
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error> {
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

impl<I> OnDiskCorpus<I>
where
    I: Input,
{
    /// Creates the [`OnDiskCorpus`].
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new<P>(dir_path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        fn new<I: Input>(dir_path: PathBuf) -> Result<OnDiskCorpus<I>, Error> {
            fs::create_dir_all(&dir_path)?;
            Ok(OnDiskCorpus {
                entries: vec![],
                current: None,
                dir_path,
                meta_format: None,
            })
        }
        new(dir_path.as_ref().to_path_buf())
    }

    /// Creates the [`OnDiskCorpus`] specifying the type of `Metadata` to be saved to disk.
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new_save_meta(
        dir_path: PathBuf,
        meta_format: Option<OnDiskMetadataFormat>,
    ) -> Result<Self, Error> {
        fs::create_dir_all(&dir_path)?;
        Ok(Self {
            entries: vec![],
            current: None,
            dir_path,
            meta_format,
        })
    }
}
#[cfg(feature = "python")]
/// `OnDiskCorpus` Python bindings
pub mod pybind {
    use std::path::PathBuf;

    use crate::corpus::OnDiskCorpus;
    use crate::inputs::BytesInput;
    use pyo3::prelude::*;
    use serde::{Deserialize, Serialize};

    #[pyclass(unsendable, name = "OnDiskCorpus")]
    #[derive(Serialize, Deserialize, Debug, Clone)]
    /// Python class for OnDiskCorpus
    pub struct PythonOnDiskCorpus {
        /// Rust wrapped OnDiskCorpus object
        pub on_disk_corpus: OnDiskCorpus<BytesInput>,
    }

    #[pymethods]
    impl PythonOnDiskCorpus {
        #[new]
        fn new(path: String) -> Self {
            Self {
                on_disk_corpus: OnDiskCorpus::new(PathBuf::from(path)).unwrap(),
            }
        }
    }
    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonOnDiskCorpus>()?;
        Ok(())
    }
}
