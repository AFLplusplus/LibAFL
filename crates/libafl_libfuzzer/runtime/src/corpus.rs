use std::{cell::RefCell, path::Path, rc::Rc};

use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, CorpusId, Testcase, TestcaseMetadata, store::DiskMgr},
    inputs::Input,
};
use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct LibfuzzerCorpus<I: Input>(CachedOnDiskCorpus<I>);

impl<I: Input> LibfuzzerCorpus<I> {
    pub fn new(root_dir: &Path, cache_max_len: usize) -> Result<Self, Error> {
        Ok(Self(
            CachedOnDiskCorpus::<I>::builder()
                .root_dir(root_dir)
                .cache_max_len(cache_max_len)
                .build()?,
        ))
    }

    pub fn dir_path(&self) -> &Path {
        self.0.fallback_store().disk_mgr().root_path()
    }
}

impl<I: Input> Corpus<I> for LibfuzzerCorpus<I> {
    type TestcaseMetadataCell = <CachedOnDiskCorpus<I> as Corpus<I>>::TestcaseMetadataCell;

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

    /// Get testcase by id
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

    fn nth(&self, nth: usize) -> CorpusId {
        self.0.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.0.nth_from_all(nth)
    }
}

/// A corpus which attempts to mimic the behaviour of libFuzzer's crash output.
#[derive(Deserialize, Serialize, Debug)]
pub struct ArtifactCorpus<I> {
    mgr: DiskMgr<I>,
    last: Option<Testcase<I, RefCell<TestcaseMetadata>>>,
    count: usize,
}

impl<I> ArtifactCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    pub fn new(root_dir: &Path) -> Result<Self, Error> {
        Ok(Self {
            mgr: DiskMgr::new(root_dir.to_path_buf())?,
            last: None,
            count: 0,
        })
    }
}

impl<I> Corpus<I> for ArtifactCorpus<I>
where
    I: Input,
{
    type TestcaseMetadataCell = RefCell<TestcaseMetadata>;

    fn count(&self) -> usize {
        self.count
    }

    // ArtifactCorpus disregards disabled entries
    fn count_disabled(&self) -> usize {
        0
    }

    fn count_all(&self) -> usize {
        // count_disabled will always return 0
        self.count() + self.count_disabled()
    }

    fn add_shared<const ENABLED: bool>(
        &mut self,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<CorpusId, Error> {
        if !ENABLED {
            unimplemented!("ArtifactCorpus disregards disabled inputs")
        }

        let idx = self.count;
        self.count += 1;

        self.mgr.save_input(input.as_ref(), &md)?;
        let testcase = Testcase::new(input, RefCell::new(md));

        // we DO NOT save metadata!
        self.last = Some(testcase);

        Ok(CorpusId::from(idx))
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        let maybe_last = if self
            .count
            .checked_sub(1)
            .map(CorpusId::from)
            .is_some_and(|last| last == id)
        {
            self.last.clone()
        } else {
            None
        };

        maybe_last.ok_or_else(|| Error::illegal_argument("Can only get the last corpus ID."))
    }

    fn disable(&mut self, _id: CorpusId) -> Result<(), Error> {
        unimplemented!("ArtifactCorpus disregards disabled inputs")
    }

    fn replace_metadata(
        &mut self,
        _id: CorpusId,
        _md: TestcaseMetadata,
    ) -> Result<Self::TestcaseMetadataCell, Error> {
        unimplemented!("ArtifactCorpus does not store metadata")
    }

    // This just calls Self::nth as ArtifactCorpus disregards disabled entries
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.nth(nth)
    }

    fn current(&self) -> &Option<CorpusId> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn next(&self, _id: CorpusId) -> Option<CorpusId> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn prev(&self, _id: CorpusId) -> Option<CorpusId> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn first(&self) -> Option<CorpusId> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn last(&self) -> Option<CorpusId> {
        self.count.checked_sub(1).map(CorpusId::from)
    }
}
