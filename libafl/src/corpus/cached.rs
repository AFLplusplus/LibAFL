//! The ondisk corpus stores unused testcases to disk.

use alloc::vec::Vec;
use core::cell::RefCell;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{corpus::{ondisk::OnDiskCorpus, Testcase, Corpus}, inputs::Input, Error};

/// A corpus able to store testcases to disk, and load them from disk, when they are being used.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct CachedOnDiskCorpus<I>
where
    I: Input,
{
    inner: OnDiskCorpus<I>,
    cached_indexes: Vec<usize>,
    cache_size: usize,
    cache_max: usize
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
    fn add(&mut self, mut testcase: Testcase<I>) -> Result<usize, Error> {
        self.inner.add(testcase)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), Error> {
        // TODO finish
        self.inner.replace(idx, testcase)?;
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, idx: usize) -> Result<Option<Testcase<I>>, Error> {
        let testcase = self.inner.remove(idx)?;
        match testcase {
            Some(t) => {
                if t.input().is_some() {
                    let size = t.input().size_of();
                    if size > self.cache_size {
                        self.cache_size = 0;
                    } else {
                        self.cache_size -= size;
                    }
                }
            }
        }
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> Result<&RefCell<Testcase<I>>, Error> {
        let testcase = self.inner.get(idx)?;
        if testcase.borrow().input().is_none() {
            let size = testcase.borrow_mut().load_input()?.size_of();
            
        }
        Ok(testcase)
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

impl<I> CachedOnDiskCorpus<I>
where
    I: Input,
{
    /// Creates the [`CachedOnDiskCorpus`].
    pub fn new(dir_path: PathBuf, cache_max_size: usize) -> Result<Self, Error> {
        Ok(Self {
            inner: OnDiskCorpus::new(dir_path),
            cache_size: 0,
            cache_max: cache_max_size
        })
    }

    /// Creates the [`CachedOnDiskCorpus`] specifying the type of `Metadata` to be saved to disk.
    pub fn new_save_meta(
        dir_path: PathBuf,
        meta_format: Option<OnDiskMetadataFormat>,
        cache_max_size: usize
    ) -> Result<Self, Error> {
        fOk(Self {
            inner: OnDiskCorpus::new_save_meta(dir_path, meta_format),
            cache_size: 0,
            cache_max: cache_max_size
        })
    }
    
    
}
