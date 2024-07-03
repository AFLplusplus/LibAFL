//! The [`CachedOnDiskCorpus`] stores [`Testcase`]s to disk, keeping a subset of them in memory/cache, evicting in a FIFO manner.

use alloc::{collections::vec_deque::VecDeque, string::String};
use core::cell::RefCell;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    corpus::{
        inmemory_ondisk::InMemoryOnDiskCorpus, ondisk::OnDiskMetadataFormat, Corpus, CorpusId,
        HasTestcase, Testcase,
    },
    inputs::{Input, UsesInput},
    Error,
};

/// A corpus that keeps a maximum number of [`Testcase`]s in memory
/// and load them from disk, when they are being used.
/// The eviction policy is FIFO.
#[cfg(feature = "std")]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct CachedOnDiskCorpus<I>
where
    I: Input,
{
    inner: InMemoryOnDiskCorpus<I>,
    cached_indexes: RefCell<VecDeque<CorpusId>>,
    cache_max_len: usize,
}

impl<I> UsesInput for CachedOnDiskCorpus<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> CachedOnDiskCorpus<I>
where
    I: Input,
{
    fn cache_testcase<'a>(
        &'a self,
        testcase: &'a RefCell<Testcase<I>>,
        id: CorpusId,
    ) -> Result<(), Error> {
        if testcase.borrow().input().is_none() {
            self.load_input_into(&mut testcase.borrow_mut())?;
            let mut borrowed_num = 0;
            while self.cached_indexes.borrow().len() >= self.cache_max_len {
                let removed = self.cached_indexes.borrow_mut().pop_front().unwrap();

                if let Ok(mut borrowed) = self.inner.get_from_all(removed)?.try_borrow_mut() {
                    *borrowed.input_mut() = None;
                } else {
                    self.cached_indexes.borrow_mut().push_back(removed);
                    borrowed_num += 1;
                    if self.cache_max_len == borrowed_num {
                        break;
                    }
                }
            }
            self.cached_indexes.borrow_mut().push_back(id);
        }
        Ok(())
    }
}
impl<I> Corpus for CachedOnDiskCorpus<I>
where
    I: Input,
{
    /// Returns the number of all enabled entries
    #[inline]
    fn count(&self) -> usize {
        self.inner.count()
    }

    /// Returns the number of all disabled entries
    fn count_disabled(&self) -> usize {
        self.inner.count_disabled()
    }

    /// Returns the number of elements including disabled entries
    #[inline]
    fn count_all(&self) -> usize {
        self.inner.count_all()
    }

    /// Add an enabled testcase to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        self.inner.add(testcase)
    }

    /// Add a disabled testcase to the corpus and return its index
    #[inline]
    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        self.inner.add_disabled(testcase)
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        // TODO finish
        self.inner.replace(id, testcase)
    }

    /// Removes an entry from the corpus, returning it if it was present; considers both enabled and disabled testcases.
    fn remove(&mut self, id: CorpusId) -> Result<Testcase<Self::Input>, Error> {
        let testcase = self.inner.remove(id)?;
        self.cached_indexes.borrow_mut().retain(|e| *e != id);
        Ok(testcase)
    }

    /// Get by id; considers only enabled testcases
    #[inline]
    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        let testcase = { self.inner.get(id)? };
        self.cache_testcase(testcase, id)?;
        Ok(testcase)
    }
    /// Get by id; considers both enabled and disabled testcases
    #[inline]
    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error> {
        let testcase = { self.inner.get_from_all(id)? };
        self.cache_testcase(testcase, id)?;
        Ok(testcase)
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
    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.inner.next(id)
    }

    /// Peek the next free corpus id
    #[inline]
    fn peek_free_id(&self) -> CorpusId {
        self.inner.peek_free_id()
    }

    #[inline]
    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.inner.prev(id)
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        self.inner.first()
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        self.inner.last()
    }

    /// Get the nth corpus id; considers only enabled testcases
    #[inline]
    fn nth(&self, nth: usize) -> CorpusId {
        self.inner.nth(nth)
    }
    /// Get the nth corpus id; considers both enabled and disabled testcases
    #[inline]
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.inner.nth_from_all(nth)
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

impl<I> HasTestcase for CachedOnDiskCorpus<I>
where
    I: Input,
{
    fn testcase(&self, id: CorpusId) -> Result<core::cell::Ref<Testcase<Self::Input>>, Error> {
        Ok(self.get(id)?.borrow())
    }

    fn testcase_mut(
        &self,
        id: CorpusId,
    ) -> Result<core::cell::RefMut<Testcase<Self::Input>>, Error> {
        Ok(self.get(id)?.borrow_mut())
    }
}

impl<I> CachedOnDiskCorpus<I>
where
    I: Input,
{
    /// Creates the [`CachedOnDiskCorpus`].
    ///
    /// This corpus stores (and reads) all testcases to/from disk
    ///
    /// By default, it stores metadata for each [`Testcase`] as prettified json.
    /// Metadata will be written to a file named `.<testcase>.metadata`
    /// the metadata may include objective reason, specific information for a fuzz job, and more.
    ///
    /// If you don't want metadata, use [`CachedOnDiskCorpus::no_meta`].
    /// to pick a different metadata format, use [`CachedOnDiskCorpus::with_meta_format`].
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn new<P>(dir_path: P, cache_max_len: usize) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(InMemoryOnDiskCorpus::new(dir_path)?, cache_max_len)
    }

    /// Creates an [`CachedOnDiskCorpus`] that does not store [`Testcase`] metadata to disk.
    pub fn no_meta<P>(dir_path: P, cache_max_len: usize) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(InMemoryOnDiskCorpus::no_meta(dir_path)?, cache_max_len)
    }

    /// Creates the [`CachedOnDiskCorpus`] specifying the format in which `Metadata` will be saved to disk.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format<P>(
        dir_path: P,
        cache_max_len: usize,
        meta_format: Option<OnDiskMetadataFormat>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(
            InMemoryOnDiskCorpus::with_meta_format(dir_path, meta_format)?,
            cache_max_len,
        )
    }

    /// Creates the [`CachedOnDiskCorpus`] specifying the metadata format and the prefix to prepend
    /// to each testcase.
    ///
    /// Will error, if [`std::fs::create_dir_all()`] failed for `dir_path`.
    pub fn with_meta_format_and_prefix<P>(
        dir_path: P,
        cache_max_len: usize,
        meta_format: Option<OnDiskMetadataFormat>,
        prefix: Option<String>,
        locking: bool,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::_new(
            InMemoryOnDiskCorpus::with_meta_format_and_prefix(
                dir_path,
                meta_format,
                prefix,
                locking,
            )?,
            cache_max_len,
        )
    }

    /// Internal constructor `fn`
    fn _new(on_disk_corpus: InMemoryOnDiskCorpus<I>, cache_max_len: usize) -> Result<Self, Error> {
        if cache_max_len == 0 {
            return Err(Error::illegal_argument(
                "The max cache len in CachedOnDiskCorpus cannot be 0",
            ));
        }
        Ok(Self {
            inner: on_disk_corpus,
            cached_indexes: RefCell::new(VecDeque::new()),
            cache_max_len,
        })
    }

    /// Fetch the inner corpus
    pub fn inner(&self) -> &InMemoryOnDiskCorpus<I> {
        &self.inner
    }
}
