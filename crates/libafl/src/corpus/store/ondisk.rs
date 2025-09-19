//! An on-disk store

use alloc::{rc::Rc, string::String, vec::Vec};
use core::{
    cell::{Ref, RefCell, RefMut},
    marker::PhantomData,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(feature = "gzip")]
use libafl_bolts::compress::GzipCompressor;
use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use super::{InMemoryCorpusMap, Store};
use crate::{
    corpus::{
        CorpusId, Testcase,
        testcase::{IsTestcaseMetadataCell, TestcaseMetadata},
    },
    inputs::Input,
};

/// An on-disk store
///
/// The maps only store the unique ID associated to the added [`Testcase`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnDiskStore<I, M> {
    disk_mgr: Rc<DiskMgr<I>>,
    enabled_map: M,
    disabled_map: M,
    first: Option<CorpusId>,
    last: Option<CorpusId>,
}

/// A Disk Manager, able to load and store [`Testcase`]s
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMgr<I> {
    root_dir: PathBuf,
    md_format: OnDiskMetadataFormat,
    phantom: PhantomData<I>,
}

/// An on-disk [`Testcase`] cell.
#[derive(Debug)]
pub struct OnDiskTestcaseCell<I> {
    mgr: Rc<DiskMgr<I>>,
    id: String,
    testcase_md: RefCell<TestcaseMetadata>,
    modified: RefCell<bool>,
}

/// Options for the the format of the on-disk metadata
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

impl OnDiskMetadataFormat {
    /// Convert a [`TestcaseMetadata`] to the format [`OnDiskMetadataFormat`] and stores it in a [`Vec`].
    pub fn to_vec(&self, testcase_md: &TestcaseMetadata) -> Result<Vec<u8>, Error> {
        let json_error = |err| Error::serialize(format!("Failed to json-ify metadata: {err:?}"));

        Ok(match self {
            OnDiskMetadataFormat::Postcard => postcard::to_allocvec(testcase_md)?,
            OnDiskMetadataFormat::Json => serde_json::to_vec(&testcase_md).map_err(json_error)?,
            OnDiskMetadataFormat::JsonPretty => {
                serde_json::to_vec_pretty(&testcase_md).map_err(json_error)?
            }
            #[cfg(feature = "gzip")]
            OnDiskMetadataFormat::JsonGzip => GzipCompressor::new()
                .compress(&serde_json::to_vec_pretty(&testcase_md).map_err(json_error)?),
        })
    }

    /// Load a [`TestcaseMetadata`] from a file with a format [`OnDiskMetadataFormat`].
    pub fn from_file(&self, md_path: &Path) -> Result<TestcaseMetadata, Error> {
        let json_error = |err| Error::serialize(format!("Failed to parse metadata: {err:?}"));
        let md_serialized = fs::read(md_path)?;

        Ok(match self {
            OnDiskMetadataFormat::Postcard => postcard::from_bytes(&md_serialized)?,
            OnDiskMetadataFormat::Json => {
                serde_json::from_slice(&md_serialized).map_err(json_error)?
            }
            OnDiskMetadataFormat::JsonPretty => {
                serde_json::from_slice(&md_serialized).map_err(json_error)?
            }
            #[cfg(feature = "gzip")]
            OnDiskMetadataFormat::JsonGzip => {
                serde_json::from_slice(&GzipCompressor::new().decompress(&md_serialized)?)
                    .map_err(json_error)?
            }
        })
    }
}

impl<I> OnDiskTestcaseCell<I> {
    /// Get a new [`OnDiskTestcaseCell`].
    #[must_use]
    pub fn new(mgr: Rc<DiskMgr<I>>, id: String, testcase_md: TestcaseMetadata) -> Self {
        Self {
            mgr,
            id,
            testcase_md: RefCell::new(testcase_md),
            modified: RefCell::new(false),
        }
    }
}

impl<I> IsTestcaseMetadataCell for OnDiskTestcaseCell<I> {
    type TestcaseMetadataRef<'a>
        = Ref<'a, TestcaseMetadata>
    where
        I: 'a;
    type TestcaseMetadataRefMut<'a>
        = RefMut<'a, TestcaseMetadata>
    where
        I: 'a;

    fn testcase_metadata(&self) -> Ref<'_, TestcaseMetadata> {
        self.testcase_md.borrow()
    }

    fn testcase_metadata_mut(&self) -> RefMut<'_, TestcaseMetadata> {
        *self.modified.borrow_mut() = true;
        self.testcase_md.borrow_mut()
    }

    fn into_testcase_metadata(self) -> TestcaseMetadata {
        self.testcase_md.clone().into_inner()
    }

    fn replace_testcase_metadata(&self, _testcase_metadata: TestcaseMetadata) -> TestcaseMetadata {
        todo!()
    }

    fn flush(&self) -> Result<(), Error> {
        self.mgr.save_metadata(&self.id, &self.testcase_md.borrow())
    }
}

impl<I> Drop for OnDiskTestcaseCell<I> {
    fn drop(&mut self) {
        self.flush().unwrap();
    }
}

impl<I> DiskMgr<I> {
    /// Create a new [`DiskMgr`]
    pub fn new(root_dir: PathBuf) -> Result<Self, Error> {
        Self::new_with_format(root_dir, OnDiskMetadataFormat::default())
    }

    /// Create a new [`DiskMgr`], with a given [`OnDiskMetadataFormat`]
    pub fn new_with_format(
        root_dir: PathBuf,
        md_format: OnDiskMetadataFormat,
    ) -> Result<Self, Error> {
        Ok(Self {
            root_dir,
            md_format,
            phantom: PhantomData,
        })
    }

    fn testcase_path(&self, testcase_id: &String) -> PathBuf {
        self.root_dir.join(testcase_id)
    }

    fn testcase_md_path(&self, testcase_id: &String) -> PathBuf {
        self.root_dir.join(format!(".{testcase_id}.metadata"))
    }

    /// The file is created if it does not exist, or reused if it's already there
    pub fn save_metadata(&self, id: &String, md: &TestcaseMetadata) -> Result<(), Error> {
        let testcase_md_path = self.testcase_md_path(id);

        let mut testcase_md_f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&testcase_md_path)?;

        let testcase_md_ser = self.md_format.to_vec(md)?;
        testcase_md_f.write_all(&testcase_md_ser)?;

        Ok(())
    }
}

impl<I> DiskMgr<I>
where
    I: Input,
{
    fn save_input(&self, input: &I) -> Result<String, Error> {
        let testcase_id = Testcase::<I, OnDiskTestcaseCell<I>>::compute_id(input);
        let testcase_path = self.testcase_path(&testcase_id);
        input.to_file(testcase_path.as_path())?;

        Ok(testcase_id)
    }

    fn save_testcase(&self, input: &I, md: &TestcaseMetadata) -> Result<String, Error> {
        let id = self.save_input(input)?;
        self.save_metadata(&id, md)?;
        Ok(id)
    }

    /// prerequisite: the testcase should not have been "removed" before.
    /// also, it should only happen if it has been saved before.
    fn load_testcase(
        self: &Rc<Self>,
        testcase_id: &String,
    ) -> Result<Testcase<I, OnDiskTestcaseCell<I>>, Error> {
        let testcase_path = self.as_ref().testcase_path(testcase_id);
        let testcase_md_path = self.as_ref().testcase_md_path(testcase_id);
        let ser_fmt = self.md_format.clone();

        // let _lockfile = TestcaseLockfile::new(self, testcase_id)?;

        let input = I::from_file(testcase_path.as_path())?;
        let md = ser_fmt.from_file(testcase_md_path.as_path())?;

        Ok(Testcase::new(
            Rc::new(input),
            OnDiskTestcaseCell::new(self.clone(), testcase_id.clone(), md),
        ))
    }
}

impl<I, M> OnDiskStore<I, M>
where
    M: Default,
{
    /// Create a new [`OnDiskStore`]
    pub fn new(root: PathBuf) -> Result<Self, Error> {
        Self::new_with_format(root, OnDiskMetadataFormat::default())
    }

    /// Create a new [`OnDiskStore`], with a specified [`OnDiskMetadataFormat`].
    pub fn new_with_format(root: PathBuf, md_format: OnDiskMetadataFormat) -> Result<Self, Error> {
        let disk_mgr = Rc::new(DiskMgr::new_with_format(root, md_format)?);

        Ok(Self {
            disk_mgr,
            enabled_map: M::default(),
            disabled_map: M::default(),
            first: None,
            last: None,
        })
    }
}

impl<I, M> Store<I> for OnDiskStore<I, M>
where
    I: Input,
    M: InMemoryCorpusMap<String>,
{
    type TestcaseMetadataCell = OnDiskTestcaseCell<I>;

    fn count_all(&self) -> usize {
        self.count().saturating_add(self.count_disabled())
    }

    fn is_empty(&self) -> bool {
        self.count() == 0
    }

    fn count(&self) -> usize {
        self.enabled_map.count()
    }

    fn count_disabled(&self) -> usize {
        self.disabled_map.count()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<(), Error> {
        let testcase_id = self.disk_mgr.save_testcase(input.as_ref(), &md)?;

        if ENABLED {
            self.enabled_map.add(id, testcase_id);
        } else {
            self.disabled_map.add(id, testcase_id);
        }

        Ok(())
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        let tc_id = if ENABLED {
            self.enabled_map
                .get(id)
                .ok_or_else(|| Error::key_not_found(format!("Index not found: {id}")))?
        } else {
            self.enabled_map
                .get(id)
                .or_else(|| self.disabled_map.get(id))
                .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))?
        };

        self.disk_mgr.load_testcase(tc_id)
    }

    fn disable(&mut self, id: CorpusId) -> Result<(), Error> {
        let tc = self
            .enabled_map
            .remove(id)
            .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))?;
        self.disabled_map.add(id, tc);
        Ok(())
    }

    fn replace_metadata(
        &mut self,
        _id: CorpusId,
        _metadata: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        todo!()
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.enabled_map.prev(id)
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.enabled_map.next(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.enabled_map.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.enabled_map.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.enabled_map.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        let nb_enabled = self.enabled_map.count();
        if nth >= nb_enabled {
            self.disabled_map.nth(nth.saturating_sub(nb_enabled))
        } else {
            self.enabled_map.nth(nth)
        }
    }
}
