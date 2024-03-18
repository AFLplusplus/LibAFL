use std::{
    cell::RefCell,
    collections::{hash_map::Entry, BTreeMap, HashMap},
    io::ErrorKind,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use libafl::{
    corpus::{inmemory::TestcaseStorage, Corpus, CorpusId, Testcase},
    inputs::{Input, UsesInput},
};
use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

/// A corpus which attempts to mimic the behaviour of libFuzzer.
#[derive(Deserialize, Serialize, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct LibfuzzerCorpus<I>
where
    I: Input + Serialize,
{
    corpus_dir: PathBuf,
    loaded_mapping: RefCell<HashMap<CorpusId, u64>>,
    loaded_entries: RefCell<BTreeMap<u64, CorpusId>>,
    mapping: TestcaseStorage<I>,
    max_len: usize,

    current: Option<CorpusId>,
    next_recency: AtomicU64,
}

impl<I> LibfuzzerCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    pub fn new(corpus_dir: PathBuf, max_len: usize) -> Self {
        Self {
            corpus_dir,
            loaded_mapping: RefCell::new(HashMap::default()),
            loaded_entries: RefCell::new(BTreeMap::default()),
            mapping: TestcaseStorage::new(),
            max_len,
            current: None,
            next_recency: AtomicU64::new(0),
        }
    }

    pub fn dir_path(&self) -> &PathBuf {
        &self.corpus_dir
    }

    /// Touch this index and maybe evict an entry if we have touched an input which was unloaded.
    fn touch(&self, idx: CorpusId) -> Result<(), Error> {
        let mut loaded_mapping = self.loaded_mapping.borrow_mut();
        let mut loaded_entries = self.loaded_entries.borrow_mut();
        match loaded_mapping.entry(idx) {
            Entry::Occupied(mut e) => {
                let &old = e.get();
                let new = self.next_recency.fetch_add(1, Ordering::Relaxed);
                e.insert(new);
                loaded_entries.remove(&old);
                loaded_entries.insert(new, idx);
            }
            Entry::Vacant(e) => {
                // new entry! send it in
                let new = self.next_recency.fetch_add(1, Ordering::Relaxed);
                e.insert(new);
                loaded_entries.insert(new, idx);
            }
        }
        if loaded_entries.len() > self.max_len {
            let idx = loaded_entries.pop_first().unwrap().1; // cannot panic
            let cell = self.mapping.get(idx).ok_or_else(|| {
                Error::key_not_found(format!("Tried to evict non-existent entry {idx}"))
            })?;
            let mut tc = cell.try_borrow_mut()?;
            let _ = tc.input_mut().take();
        }
        Ok(())
    }
}

impl<I> UsesInput for LibfuzzerCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    type Input = I;
}

impl<I> Corpus for LibfuzzerCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    fn count(&self) -> usize {
        self.mapping.map.len()
    }

    fn add(&mut self, testcase: Testcase<Self::Input>) -> Result<CorpusId, Error> {
        let idx = self.mapping.insert(RefCell::new(testcase));
        let mut testcase = self.mapping.get(idx).unwrap().borrow_mut();

        match testcase.file_path() {
            Some(path) if path.canonicalize()?.starts_with(&self.corpus_dir) => {
                // if it's already in the correct dir, we retain it
            }
            _ => {
                let input = testcase.input().as_ref().ok_or_else(|| {
                    Error::empty(
                        "The testcase, when added to the corpus, must have an input present!",
                    )
                })?;
                let name = input.generate_name(idx.into());
                let path = self.corpus_dir.join(&name);

                match input.to_file(&path) {
                    Err(Error::OsError(e, ..)) if e.kind() == ErrorKind::AlreadyExists => {
                        // we do not care if the file already exists; in this case, we assume it is equal
                    }
                    res => res?,
                }

                // we DO NOT save metadata!

                testcase.filename_mut().replace(name);
                testcase.file_path_mut().replace(path);
            }
        };

        self.touch(idx)?;
        Ok(idx)
    }

    fn replace(
        &mut self,
        _idx: CorpusId,
        _testcase: Testcase<Self::Input>,
    ) -> Result<Testcase<Self::Input>, Error> {
        unimplemented!("It is unsafe to use this corpus variant with replace!");
    }

    fn remove(&mut self, _id: CorpusId) -> Result<Testcase<Self::Input>, Error> {
        unimplemented!("It is unsafe to use this corpus variant with replace!");
    }

    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error> {
        self.touch(id)?;
        self.mapping.map.get(&id).map(|item| &item.testcase).ok_or_else(|| Error::illegal_state("Nonexistent corpus entry {id} requested (present in loaded entries, but not the mapping?)"))
    }

    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.mapping.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.mapping.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.mapping.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.mapping.last()
    }

    fn load_input_into(&self, testcase: &mut Testcase<Self::Input>) -> Result<(), Error> {
        // we don't need to update the loaded testcases because it must have already been loaded
        if testcase.input().is_none() {
            let path = testcase.file_path().as_ref().ok_or_else(|| {
                Error::empty("The testcase, when being saved, must have a file path!")
            })?;
            let input = I::from_file(path)?;
            testcase.input_mut().replace(input);
        }
        Ok(())
    }

    fn store_input_from(&self, testcase: &Testcase<Self::Input>) -> Result<(), Error> {
        let input = testcase.input().as_ref().ok_or_else(|| {
            Error::empty("The testcase, when being saved, must have an input present!")
        })?;
        let path = testcase.file_path().as_ref().ok_or_else(|| {
            Error::empty("The testcase, when being saved, must have a file path!")
        })?;
        match input.to_file(path) {
            Err(Error::OsError(e, ..)) if e.kind() == ErrorKind::AlreadyExists => {
                // we do not care if the file already exists; in this case, we assume it is equal
                Ok(())
            }
            res => res,
        }
    }
}

/// A corpus which attempts to mimic the behaviour of libFuzzer's crash output.
#[derive(Deserialize, Serialize, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct ArtifactCorpus<I>
where
    I: Input + Serialize,
{
    last: Option<RefCell<Testcase<I>>>,
    count: usize,
}

impl<I> ArtifactCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    pub fn new() -> Self {
        Self {
            last: None,
            count: 0,
        }
    }
}

impl<I> UsesInput for ArtifactCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    type Input = I;
}

impl<I> Corpus for ArtifactCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    fn count(&self) -> usize {
        self.count
    }

    fn add(&mut self, testcase: Testcase<Self::Input>) -> Result<CorpusId, Error> {
        let idx = self.count;
        self.count += 1;

        let input = testcase.input().as_ref().ok_or_else(|| {
            Error::empty("The testcase, when added to the corpus, must have an input present!")
        })?;
        let path = testcase.file_path().as_ref().ok_or_else(|| {
            Error::illegal_state("Should have set the path in the LibfuzzerCrashCauseFeedback.")
        })?;
        match input.to_file(path) {
            Err(Error::OsError(e, ..)) if e.kind() == ErrorKind::AlreadyExists => {
                // we do not care if the file already exists; in this case, we assume it is equal
            }
            res => res?,
        }

        // we DO NOT save metadata!
        self.last = Some(RefCell::new(testcase));

        Ok(CorpusId::from(idx))
    }

    fn replace(
        &mut self,
        _idx: CorpusId,
        _testcase: Testcase<Self::Input>,
    ) -> Result<Testcase<Self::Input>, Error> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn remove(&mut self, _id: CorpusId) -> Result<Testcase<Self::Input>, Error> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error> {
        let maybe_last = if self
            .count
            .checked_sub(1)
            .map(CorpusId::from)
            .map_or(false, |last| last == id)
        {
            self.last.as_ref()
        } else {
            None
        };
        maybe_last.ok_or_else(|| Error::illegal_argument("Can only get the last corpus ID."))
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

    fn load_input_into(&self, _testcase: &mut Testcase<Self::Input>) -> Result<(), Error> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn store_input_from(&self, _testcase: &Testcase<Self::Input>) -> Result<(), Error> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }
}
