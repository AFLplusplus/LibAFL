//! The ondisk corpus stores unused testcases to disk.

use alloc::vec::Vec;
use core::cell::RefCell;
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::{fs, fs::File, io::Write, path::PathBuf};

use crate::{corpus::Corpus, corpus::Testcase, inputs::Input, state::HasMetadata, Error};

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
            // TODO walk entry metadata to ask for pices of filename (e.g. :havoc in AFL)
            let filename = self.dir_path.join(format!("id_{}", &self.entries.len()));
            let filename_str = filename.to_str().expect("Invalid Path");
            testcase.set_filename(filename_str.into());
        };
        if self.meta_format.is_some() {
            let filename = testcase.filename().as_ref().unwrap().to_owned() + ".metadata";
            let mut file = File::create(filename)?;

            let serialized = match self.meta_format.as_ref().unwrap() {
                OnDiskMetadataFormat::Postcard => postcard::to_allocvec(testcase.metadata())?,
                OnDiskMetadataFormat::Json => serde_json::to_vec(testcase.metadata())?,
                OnDiskMetadataFormat::JsonPretty => serde_json::to_vec_pretty(testcase.metadata())?,
            };
            file.write_all(&serialized)?;
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

    /// Current testcase scheduled (mut)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<usize> {
        &mut self.current
    }
}

impl<I> OnDiskCorpus<I>
where
    I: Input,
{
    /// Creates the OnDiskCorpus.
    /// Will error, if `std::fs::create_dir_all` failed for `dir_path`.
    pub fn new(dir_path: PathBuf) -> Result<Self, Error> {
        fs::create_dir_all(&dir_path)?;
        Ok(Self {
            entries: vec![],
            current: None,
            dir_path,
            meta_format: None,
        })
    }

    /// Creates the OnDiskCorpus specifying the type of metatada to be saved to disk.
    /// Will error, if `std::fs::create_dir_all` failed for `dir_path`.
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
