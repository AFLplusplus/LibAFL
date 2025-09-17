//! An on-disk store

use alloc::rc::Rc;
use core::marker::PhantomData;
use std::{
    cell::{Ref, RefCell, RefMut},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    string::String,
    vec::Vec,
};

use libafl_bolts::{Error, compress::GzipCompressor};
use serde::{Deserialize, Serialize};

use super::{InMemoryCorpusMap, Store};
use crate::{
    corpus::{
        CorpusId, Testcase,
        testcase::{HasTestcaseMetadata, TestcaseMetadata},
    },
    inputs::Input,
};

/// An on-disk store
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct OnDiskStore<I, M> {
    disk_mgr: Rc<DiskMgr<I>>,
    enabled_map: M,
    disabled_map: M,
    first: Option<CorpusId>,
    last: Option<CorpusId>,
}

/// A Disk Manager, able to load and store [`Testcase`]s
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DiskMgr<I> {
    root_dir: PathBuf,
    md_format: OnDiskMetadataFormat,
    phantom: PhantomData<I>,
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

/// An on-disk [`Testcase`] cell.
#[derive(Debug)]
pub struct OnDiskTestcaseCell<I> {
    mgr: Rc<DiskMgr<I>>,
    testcase_md: RefCell<TestcaseMetadata>,
    modified: bool,
}

impl<I> OnDiskTestcaseCell<I> {
    /// Get a new [`OnDiskTestcaseCell`].
    pub fn new(mgr: Rc<DiskMgr<I>>, testcase_md: TestcaseMetadata) -> Self {
        Self {
            mgr,
            testcase_md: RefCell::new(testcase_md),
            modified: false,
        }
    }
}

impl<I> HasTestcaseMetadata for OnDiskTestcaseCell<I> {
    type TestcaseMetadataRef<'a>
        = Ref<'a, TestcaseMetadata>
    where
        I: 'a;
    type TestcaseMetadataRefMut<'a>
        = RefMut<'a, TestcaseMetadata>
    where
        I: 'a;

    fn testcase_metadata<'a>(&'a self) -> Ref<'a, TestcaseMetadata> {
        self.testcase_md.borrow()
    }

    fn testcase_metadata_mut<'a>(&'a self) -> RefMut<'a, TestcaseMetadata> {
        self.testcase_md.borrow_mut()
    }

    fn into_testcase_metadata(self) -> TestcaseMetadata {
        self.testcase_md.clone().into_inner()
    }
}

impl<I> Drop for OnDiskTestcaseCell<I> {
    fn drop(&mut self) {
        todo!()
    }
}

impl<I> DiskMgr<I>
where
    I: Input,
{
    fn testcase_path(&self, testcase_id: &String) -> PathBuf {
        self.root_dir.join(&testcase_id)
    }

    fn testcase_md_path(&self, testcase_id: &String) -> PathBuf {
        self.root_dir.join(format!(".{}.metadata", testcase_id))
    }

    fn save_testcase(&self, input: Rc<I>, md: TestcaseMetadata) -> Result<String, Error> {
        let testcase_id = Testcase::<I, OnDiskTestcaseCell<I>>::compute_id(input.as_ref());
        let testcase_path = self.testcase_path(&testcase_id);
        // let mut lockfile = TestcaseLockfile::new(self, testcase_id)?;

        // if lockfile.inc_used() {
        // save md to file
        let ser_fmt = self.md_format.clone();
        let testcase_md_path = self.testcase_md_path(&testcase_id);

        let mut testcase_md_f = File::create_new(testcase_md_path.as_path()).unwrap();
        let testcase_md_ser = ser_fmt.to_vec(&md)?;

        testcase_md_f.write_all(&testcase_md_ser)?;

        // testcase_f.write_all(testcase.input().target_bytes().as_ref())?;
        input.as_ref().to_file(testcase_path.as_path())?;
        // }

        Ok(testcase_id)
    }

    /// prerequisite: the testcase should not have been "removed" before.
    /// also, it should only happen if it has been saved before.
    fn load_testcase(
        self: &Rc<Self>,
        testcase_id: &String,
    ) -> Result<Testcase<I, OnDiskTestcaseCell<I>>, Error> {
        let testcase_path = self.testcase_path(testcase_id);
        let testcase_md_path = self.testcase_md_path(testcase_id);
        let ser_fmt = self.md_format.clone();

        // let _lockfile = TestcaseLockfile::new(self, testcase_id)?;

        let input = I::from_file(testcase_path.as_path())?;
        let md = ser_fmt.from_file(testcase_md_path.as_path())?;

        Ok(Testcase::new(
            Rc::new(input),
            OnDiskTestcaseCell::new(self.clone(), md),
        ))
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

    fn add(&mut self, id: CorpusId, input: Rc<I>, md: TestcaseMetadata) -> Result<(), Error> {
        let testcase_id = self.disk_mgr.save_testcase(input, md)?;
        self.enabled_map.add(id, testcase_id);
        Ok(())
    }

    fn add_disabled(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<(), Error> {
        let testcase_id = self.disk_mgr.save_testcase(input, md)?;
        self.disabled_map.add(id, testcase_id);
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

        self.disk_mgr.load_testcase(&tc_id)
    }

    fn replace(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        let new_testcase_id = self.disk_mgr.save_testcase(input, md)?;
        let old_testcase_id = self
            .enabled_map
            .replace(id, new_testcase_id)
            .ok_or_else(|| Error::key_not_found(format!("Index not found: {id}")))?;
        self.disk_mgr.load_testcase(&old_testcase_id)
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
