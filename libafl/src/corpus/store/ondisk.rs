use core::{cell::RefCell, marker::PhantomData};
use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
    string::String,
    vec::Vec,
};

use fs4::fs_std::FileExt;
use libafl_bolts::{Error, compress::GzipCompressor};
use serde::{Deserialize, Serialize};

use super::{InMemoryCorpusMap, Store};
use crate::{
    corpus::{CorpusId, Testcase, testcase::TestcaseMetadata},
    inputs::Input,
};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct OnDiskStore<I, M> {
    disk_mgr: DiskMgr<I>,
    enabled_map: M,
    disabled_map: M,
    first: Option<CorpusId>,
    last: Option<CorpusId>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct DiskMgr<I> {
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

#[derive(Debug)]
struct TestcaseLockfile {
    lockfile: File,
    nb_used: u32,
}

impl TestcaseLockfile {
    pub fn new<I>(ondisk_mgr: &DiskMgr<I>, testcase_id: &String) -> Result<Self, Error> {
        let lockfile_path = ondisk_mgr.root_dir.join(format!(".{}.lock", testcase_id));

        let mut lockfile = match File::create_new(lockfile_path.as_path()) {
            Ok(f) => f,
            Err(e) => match e.kind() {
                io::ErrorKind::AlreadyExists => File::open(lockfile_path.as_path()).unwrap(),

                _ => return Err(e.into()),
            },
        };

        lockfile.lock_exclusive()?;

        let mut nb_used_buf: [u8; 4] = [0; 4];
        let nb_used: u32 = match lockfile.read_exact(&mut nb_used_buf) {
            Ok(()) => u32::from_le_bytes(nb_used_buf),
            Err(e) => match e.kind() {
                io::ErrorKind::UnexpectedEof => 0,

                _ => return Err(e.into()),
            },
        };

        Ok(Self { lockfile, nb_used })
    }

    /// returns true if it is the first use
    pub fn inc_used(&mut self) -> bool {
        self.nb_used += 1;
        self.nb_used == 1
    }

    /// returns true if not in used anymore
    /// can be safely deleted
    pub fn dec_used(&mut self) -> bool {
        if self.nb_used == 0 {
            true
        } else {
            self.nb_used -= 1;
            self.nb_used == 0
        }
    }
}

impl Drop for TestcaseLockfile {
    fn drop(&mut self) {
        let nb_used_buf = self.nb_used.to_le_bytes();

        self.lockfile.seek(SeekFrom::Start(0));
        self.lockfile.write_all(&nb_used_buf).unwrap();

        FileExt::unlock(&self.lockfile);
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

    fn save_testcase(&self, testcase: &Testcase<I>) -> Result<String, Error> {
        let testcase_id = testcase.id();
        let testcase_path = self.testcase_path(testcase_id);
        let mut lockfile = TestcaseLockfile::new(self, testcase_id)?;

        if lockfile.inc_used() {
            // save md to file
            let ser_fmt = self.md_format.clone();
            let testcase_md_path = self.testcase_md_path(testcase_id);

            let mut testcase_md_f = File::create_new(testcase_md_path.as_path()).unwrap();
            let testcase_md_ser = ser_fmt.to_vec(testcase.metadata())?;

            testcase_md_f.write_all(&testcase_md_ser)?;

            // testcase_f.write_all(testcase.input().target_bytes().as_ref())?;
            testcase.input().to_file(testcase_path.as_path())?;
        }

        Ok(testcase_id.clone())
    }

    /// prerequisite: the testcase should not have been "removed" before.
    /// also, it should only happen if it has been saved before.
    fn load_testcase(&self, testcase_id: &String) -> Result<Testcase<I>, Error> {
        let testcase_path = self.testcase_path(testcase_id);
        let testcase_md_path = self.testcase_md_path(testcase_id);
        let ser_fmt = self.md_format.clone();

        let _lockfile = TestcaseLockfile::new(self, testcase_id)?;

        let input = I::from_file(testcase_path.as_path())?;
        let md = ser_fmt.from_file(testcase_md_path.as_path())?;

        Ok(Testcase::new(input, md))
    }

    fn remove_testcase(&self, testcase_id: &String) -> Result<(), Error> {
        let mut lockfile = TestcaseLockfile::new(self, testcase_id)?;

        if lockfile.dec_used() {
            fs::remove_file(self.testcase_path(testcase_id))?;
            fs::remove_file(self.testcase_md_path(testcase_id))?;
        }

        Ok(())
    }
}

impl<I, M> Store<I> for OnDiskStore<I, M>
where
    I: Input,
    M: InMemoryCorpusMap<String>,
{
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

    fn add(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<(), Error> {
        let testcase_id = self.disk_mgr.save_testcase(&testcase)?;
        self.enabled_map.add(id, testcase_id);
        Ok(())
    }

    fn add_disabled(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<(), Error> {
        let testcase_id = self.disk_mgr.save_testcase(&testcase)?;
        self.disabled_map.add(id, testcase_id);
        Ok(())
    }

    fn replace(&mut self, id: CorpusId, new_testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        let new_tc_id = self.disk_mgr.save_testcase(&new_testcase)?;
        let old_tc_id = self.enabled_map.replace(id, new_tc_id).ok_or_else(|| {
            Error::key_not_found(format!("Index {id} not found, could not replace."))
        })?;

        let old_tc = self.disk_mgr.load_testcase(&old_tc_id)?;
        self.disk_mgr.remove_testcase(&old_tc_id)?;
        Ok(old_tc)
    }

    fn remove(&mut self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        let old_tc_id = self
            .enabled_map
            .remove(id)
            .or_else(|| self.disabled_map.remove(id))
            .ok_or(Error::key_not_found(format!("Index {id} not found")))?;

        let old_tc_id_borrowed = old_tc_id.borrow();
        let old_tc = self.disk_mgr.load_testcase(&old_tc_id_borrowed)?;
        self.disk_mgr.remove_testcase(&old_tc_id_borrowed)?;
        Ok(Rc::new(RefCell::new(old_tc)))
    }

    fn get(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        let tc_id = self
            .enabled_map
            .get(id)
            .ok_or(Error::key_not_found(format!("Index not found: {id}")))?;

        let tc_id_borrowed = tc_id.borrow();
        let tc = self.disk_mgr.load_testcase(&*tc_id_borrowed)?;
        Ok(Rc::new(RefCell::new(tc)))
    }

    fn get_from_all(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        let tc_id = self
            .enabled_map
            .get(id)
            .or_else(|| self.disabled_map.get(id))
            .ok_or(Error::key_not_found(format!("Index {id} not found")))?;

        let tc_id_borrowed = tc_id.borrow();
        let tc = self.disk_mgr.load_testcase(&*&tc_id_borrowed)?;
        Ok(Rc::new(RefCell::new(tc)))
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
