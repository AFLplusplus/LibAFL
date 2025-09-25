//! A collection of various [`Corpus`].

use alloc::{rc::Rc, string::String};
use core::cell::RefCell;
use std::path::{Path, PathBuf};

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{
        CombinedCorpus, Corpus, CorpusId, FifoCache, IdentityCache, InMemoryStore, OnDiskStore,
        SingleCorpus, Testcase, TestcaseFilenameFormat, TestcaseMetadata,
        cache::StdIdentityCacheTestcaseMetadataCell,
        maps::{self, InMemoryCorpusMap, InMemoryTestcaseMap},
        store::{OnDiskMetadataFormat, Store, ondisk::OnDiskStoreBuilder},
    },
    inputs::Input,
};

const DEFAULT_CACHE_LEN: usize = 32;

#[cfg(not(feature = "corpus_btreemap"))]
type StdInMemoryMap<T> = maps::HashCorpusMap<T>;
#[cfg(feature = "corpus_btreemap")]
type StdInMemoryMap<T> = maps::BtreeCorpusMap<T>;

type StdInMemoryTestcaseMetadataCell = Rc<RefCell<TestcaseMetadata>>;
type StdInMemoryTestcase<I> = Testcase<I, StdInMemoryTestcaseMetadataCell>;
type InnerStdInMemoryCorpusMap<I> = StdInMemoryMap<StdInMemoryTestcase<I>>;
type InnerStdInMemoryStore<I> =
    InMemoryStore<I, InnerStdInMemoryCorpusMap<I>, StdInMemoryTestcaseMetadataCell>;
type InnerInMemoryCorpus<I> = SingleCorpus<I, InnerStdInMemoryStore<I>>;

//type StdOnDiskTestcaseMetadataCell<I> = Rc<OnDiskTestcaseCell<I>>;
//type StdOnDiskTestcase<I> = Testcase<I, StdOnDiskTestcaseMetadataCell<I>>;
//type InnerStdOnDiskCorpusMap<I> = StdInMemoryMap<StdOnDiskTestcase<I>>;
type InnerStdOnDiskStore<I> = OnDiskStore<I, StdInMemoryMap<String>>;
#[cfg(feature = "std")]
type InnerOnDiskCorpus<I> = SingleCorpus<I, InnerStdOnDiskStore<I>>;

type InnerInMemoryOnDiskCorpus<I> = CombinedCorpus<
    IdentityCache<
        StdInMemoryMap<
            Testcase<
                I,
                StdIdentityCacheTestcaseMetadataCell<
                    I,
                    InnerStdInMemoryStore<I>,
                    InnerStdOnDiskStore<I>,
                >,
            >,
        >,
    >,
    InnerStdInMemoryStore<I>,
    InnerStdOnDiskStore<I>,
    I,
>;

type InnerCachedOnDiskCorpus<I> = CombinedCorpus<
    FifoCache<InnerStdInMemoryStore<I>, InnerStdOnDiskStore<I>, I>,
    InnerStdInMemoryStore<I>,
    InnerStdOnDiskStore<I>,
    I,
>;

/// The standard fully in-memory corpus map.
#[repr(transparent)]
#[derive(Debug, Serialize)]
pub struct StdInMemoryCorpusMap<I>(InnerStdInMemoryCorpusMap<I>);

/// The standard fully in-memory store.
#[repr(transparent)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StdInMemoryStore<I>(InnerStdInMemoryStore<I>);

/// The standard fully on-disk store.
#[repr(transparent)]
#[derive(Debug, Serialize)]
pub struct StdOnDiskStore<I>(InnerStdOnDiskStore<I>);

/// The standard in-memory corpus.
#[repr(transparent)]
#[derive(Debug, Serialize, Deserialize)]
pub struct InMemoryCorpus<I>(InnerInMemoryCorpus<I>);

/// The standard fully on-disk corpus.
#[cfg(feature = "std")]
#[repr(transparent)]
#[derive(Debug, Serialize, Deserialize)]
pub struct OnDiskCorpus<I>(InnerOnDiskCorpus<I>);

/// The on-disk corpus builder
#[cfg(feature = "std")]
#[derive(Debug, Clone, Default)]
pub struct OnDiskCorpusBuilder(OnDiskStoreBuilder);

/// The standard corpus for storing on disk and in-memory with a cache.
/// Useful for very large corpuses.
#[repr(transparent)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct CachedOnDiskCorpus<I: Input>(InnerCachedOnDiskCorpus<I>);

/// The cached on-disk corpus builder
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct CachedOnDiskCorpusBuilder {
    store_builder: OnDiskStoreBuilder,
    cache_max_len: usize,
}

/// The standard corpus for storing on disk and in-memory.
#[repr(transparent)]
#[derive(Debug, Serialize)]
pub struct InMemoryOnDiskCorpus<I: Input>(InnerInMemoryOnDiskCorpus<I>);

impl<I> InMemoryCorpusMap<StdInMemoryTestcase<I>> for StdInMemoryCorpusMap<I>
where
    I: Input,
{
    fn count(&self) -> usize {
        self.0.count()
    }

    fn add(&mut self, id: CorpusId, testcase: Testcase<I, Rc<RefCell<TestcaseMetadata>>>) {
        self.0.add(id, testcase);
    }

    fn get(&self, id: CorpusId) -> Option<&Testcase<I, Rc<RefCell<TestcaseMetadata>>>> {
        self.0.get(id)
    }

    fn get_mut(&mut self, id: CorpusId) -> Option<&mut Testcase<I, Rc<RefCell<TestcaseMetadata>>>> {
        self.0.get_mut(id)
    }

    fn remove(&mut self, id: CorpusId) -> Option<Testcase<I, Rc<RefCell<TestcaseMetadata>>>> {
        self.0.remove(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.prev(id)
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.next(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.0.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.0.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.0.nth(nth)
    }
}

impl<I> InMemoryTestcaseMap<StdInMemoryTestcase<I>> for StdInMemoryCorpusMap<I>
where
    I: Input,
{
    fn replace_metadata(
        &mut self,
        id: CorpusId,
        testcase_metadata: TestcaseMetadata,
    ) -> Option<TestcaseMetadata> {
        self.0.replace_metadata(id, testcase_metadata)
    }
}

impl<I> Store<I> for StdInMemoryStore<I>
where
    I: Input,
{
    type TestcaseMetadataCell = <InnerStdInMemoryStore<I> as Store<I>>::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.0.count()
    }

    fn count_disabled(&self) -> usize {
        self.0.count_disabled()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<(), Error> {
        self.0.add_shared::<ENABLED>(id, input, md)
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.0.get_from::<ENABLED>(id)
    }

    fn disable(&mut self, id: CorpusId) -> Result<(), Error> {
        self.0.disable(id)
    }

    fn replace_metadata(
        &mut self,
        id: CorpusId,
        metadata: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        self.0.replace_metadata(id, metadata)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.prev(id)
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.next(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.0.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.0.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.0.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.0.nth_from_all(nth)
    }
}

impl<I> Store<I> for StdOnDiskStore<I>
where
    I: Input,
{
    type TestcaseMetadataCell = <InnerStdOnDiskStore<I> as Store<I>>::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.0.count()
    }

    fn count_disabled(&self) -> usize {
        self.0.count_disabled()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<(), Error> {
        self.0.add_shared::<ENABLED>(id, input, md)
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.0.get_from::<ENABLED>(id)
    }

    fn disable(&mut self, id: CorpusId) -> Result<(), Error> {
        self.0.disable(id)
    }

    fn replace_metadata(
        &mut self,
        id: CorpusId,
        metadata: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        self.0.replace_metadata(id, metadata)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.prev(id)
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.next(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.0.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.0.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.0.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.0.nth_from_all(nth)
    }
}

impl<I> Default for InMemoryCorpus<I> {
    fn default() -> Self {
        InMemoryCorpus(InnerInMemoryCorpus::default())
    }
}

impl<I> InMemoryCorpus<I> {
    /// Create a new [`InMemoryCorpus`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I> Corpus<I> for InMemoryCorpus<I>
where
    I: Input,
{
    type TestcaseMetadataCell = <InnerInMemoryCorpus<I> as Corpus<I>>::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.0.count()
    }

    fn count_disabled(&self) -> usize {
        self.0.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.0.count_all()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error> {
        self.0.add_shared::<ENABLED>(input, md)
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.0.get_from::<ENABLED>(id)
    }

    fn disable(&mut self, id: CorpusId) -> Result<(), Error> {
        self.0.disable(id)
    }

    fn replace_metadata(
        &mut self,
        id: CorpusId,
        md: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        self.0.replace_metadata(id, md)
    }

    fn current(&self) -> &Option<CorpusId> {
        self.0.current()
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        self.0.current_mut()
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.0.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.0.last()
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.0.nth_from_all(nth)
    }
}

#[cfg(feature = "std")]
impl OnDiskCorpusBuilder {
    /// Create a new [`OnDiskCorpusBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the root directory, where the testcases will be stored.
    pub fn root_dir(&mut self, root: &Path) -> &mut Self {
        self.0.root_dir(root);
        self
    }

    /// Set the on-disk filename format
    pub fn filename_format(&mut self, filename_format: TestcaseFilenameFormat) -> &mut Self {
        self.0.filename_format(filename_format);
        self
    }

    /// Set the metadata serialization format.
    pub fn md_format(&mut self, md_format: OnDiskMetadataFormat) -> &mut Self {
        self.0.md_format(md_format);
        self
    }

    /// Build an [`OnDiskStore`].
    /// The root directory must be set.
    pub fn build<I>(&self) -> Result<OnDiskCorpus<I>, Error> {
        Ok(OnDiskCorpus(SingleCorpus::new(self.0.build()?)))
    }
}

#[cfg(feature = "std")]
impl<I> OnDiskCorpus<I>
where
    I: Input,
{
    /// Create a new [`OnDiskCorpus`]
    pub fn new(
        root: PathBuf,
        filename_format: TestcaseFilenameFormat,
        md_format: OnDiskMetadataFormat,
    ) -> Result<Self, Error> {
        Ok(OnDiskCorpus(InnerOnDiskCorpus::new(
            InnerStdOnDiskStore::new(root, filename_format, md_format)?,
        )))
    }

    /// Get a [`OnDiskCorpus`] builder.
    #[must_use]
    pub fn builder() -> OnDiskCorpusBuilder {
        OnDiskCorpusBuilder::default()
    }
}

#[cfg(feature = "std")]
impl<I> Corpus<I> for OnDiskCorpus<I>
where
    I: Input,
{
    type TestcaseMetadataCell = <InnerOnDiskCorpus<I> as Corpus<I>>::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.0.count()
    }

    fn count_disabled(&self) -> usize {
        self.0.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.0.count_all()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error> {
        self.0.add_shared::<ENABLED>(input, md)
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.0.get_from::<ENABLED>(id)
    }

    fn disable(&mut self, id: CorpusId) -> Result<(), Error> {
        self.0.disable(id)
    }

    fn replace_metadata(
        &mut self,
        id: CorpusId,
        md: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        self.0.replace_metadata(id, md)
    }

    fn current(&self) -> &Option<CorpusId> {
        self.0.current()
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        self.0.current_mut()
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.0.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.0.last()
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.0.nth_from_all(nth)
    }
}

impl<I> Corpus<I> for InMemoryOnDiskCorpus<I>
where
    I: Input,
{
    type TestcaseMetadataCell = <InnerInMemoryOnDiskCorpus<I> as Corpus<I>>::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.0.count()
    }

    fn count_disabled(&self) -> usize {
        self.0.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.0.count_all()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error> {
        self.0.add_shared::<ENABLED>(input, md)
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.0.get_from::<ENABLED>(id)
    }

    fn disable(&mut self, id: CorpusId) -> Result<(), Error> {
        self.0.disable(id)
    }

    fn replace_metadata(
        &mut self,
        id: CorpusId,
        md: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        self.0.replace_metadata(id, md)
    }

    fn current(&self) -> &Option<CorpusId> {
        self.0.current()
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        self.0.current_mut()
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.0.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.0.last()
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.0.nth_from_all(nth)
    }
}

impl<I: Input> Corpus<I> for CachedOnDiskCorpus<I> {
    type TestcaseMetadataCell = <InnerCachedOnDiskCorpus<I> as Corpus<I>>::TestcaseMetadataCell;

    fn count(&self) -> usize {
        self.0.count()
    }

    fn count_disabled(&self) -> usize {
        self.0.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.0.count_all()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error> {
        self.0.add_shared::<ENABLED>(input, md)
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        self.0.get_from::<ENABLED>(id)
    }

    fn disable(&mut self, id: CorpusId) -> Result<(), Error> {
        self.0.disable(id)
    }

    fn replace_metadata(
        &mut self,
        id: CorpusId,
        md: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        self.0.replace_metadata(id, md)
    }

    fn current(&self) -> &Option<CorpusId> {
        self.0.current()
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        self.0.current_mut()
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.0.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.0.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.0.last()
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.0.nth_from_all(nth)
    }
}

impl<I: Input> CachedOnDiskCorpus<I> {
    /// Get a [`CachedOnDiskCorpus`] builder.
    #[must_use]
    pub fn builder() -> CachedOnDiskCorpusBuilder {
        CachedOnDiskCorpusBuilder::new()
    }

    /// Get the fallback store
    pub fn fallback_store(&self) -> &InnerStdOnDiskStore<I> {
        self.0.fallback_store()
    }
}

impl Default for CachedOnDiskCorpusBuilder {
    fn default() -> Self {
        Self {
            store_builder: OnDiskStoreBuilder::new(),
            cache_max_len: DEFAULT_CACHE_LEN,
        }
    }
}

#[cfg(feature = "std")]
impl CachedOnDiskCorpusBuilder {
    /// Create a new [`CachedOnDiskCorpusBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the cache max length.
    pub fn cache_max_len(&mut self, cache_max_len: usize) -> &mut Self {
        self.cache_max_len = cache_max_len;
        self
    }

    /// Set the root directory, where the testcases will be stored.
    pub fn root_dir(&mut self, root: &Path) -> &mut Self {
        self.store_builder.root_dir(root);
        self
    }

    /// Set the on-disk filename format
    pub fn filename_format(&mut self, filename_format: TestcaseFilenameFormat) -> &mut Self {
        self.store_builder.filename_format(filename_format);
        self
    }

    /// Set the metadata serialization format.
    pub fn md_format(&mut self, md_format: OnDiskMetadataFormat) -> &mut Self {
        self.store_builder.md_format(md_format);
        self
    }

    /// Build an [`OnDiskStore`].
    /// The root directory must be set.
    pub fn build<I: Input>(&self) -> Result<CachedOnDiskCorpus<I>, Error> {
        Ok(CachedOnDiskCorpus(CombinedCorpus::new(
            FifoCache::new(self.cache_max_len),
            InnerStdInMemoryStore::default(),
            self.store_builder.build()?,
        )))
    }
}
