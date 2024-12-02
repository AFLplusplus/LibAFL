use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::ErrorKind,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use hashbrown::{hash_map::Entry, HashMap};
use libafl::{
    corpus::{
        inmemory::{TestcaseStorage, TestcaseStorageMap},
        Corpus, CorpusId, Testcase,
    },
    inputs::Input,
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
    fn touch(&self, id: CorpusId, corpus: &TestcaseStorageMap<I>) -> Result<(), Error> {
        let mut loaded_mapping = self.loaded_mapping.borrow_mut();
        let mut loaded_entries = self.loaded_entries.borrow_mut();
        match loaded_mapping.entry(id) {
            Entry::Occupied(mut e) => {
                let &old = e.get();
                let new = self.next_recency.fetch_add(1, Ordering::Relaxed);
                e.insert(new);
                loaded_entries.remove(&old);
                loaded_entries.insert(new, id);
            }
            Entry::Vacant(e) => {
                // new entry! send it in
                let new = self.next_recency.fetch_add(1, Ordering::Relaxed);
                e.insert(new);
                loaded_entries.insert(new, id);
            }
        }
        if loaded_entries.len() > self.max_len {
            let id = loaded_entries.pop_first().unwrap().1; // cannot panic
            let cell = corpus.get(id).ok_or_else(|| {
                Error::key_not_found(format!("Tried to evict non-existent entry {id}"))
            })?;
            let mut tc = cell.try_borrow_mut()?;
            let _ = tc.input_mut().take();
        }
        Ok(())
    }
    #[inline]
    fn _get<'a>(
        &'a self,
        id: CorpusId,
        corpus: &'a TestcaseStorageMap<I>,
    ) -> Result<&RefCell<Testcase<I>>, Error> {
        self.touch(id, corpus)?;
        corpus.map.get(&id).map(|item| &item.testcase).ok_or_else(|| Error::illegal_state("Nonexistent corpus entry {id} requested (present in loaded entries, but not the mapping?)"))
    }

    fn _add(
        &mut self,
        testcase: RefCell<Testcase<I>>,
        is_disabled: bool,
    ) -> Result<CorpusId, Error> {
        let id = if is_disabled {
            self.mapping.insert_disabled(testcase)
        } else {
            self.mapping.insert(testcase)
        };
        let corpus = if is_disabled {
            &self.mapping.disabled
        } else {
            &self.mapping.enabled
        };
        let mut testcase = corpus.get(id).unwrap().borrow_mut();
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
                let name = input.generate_name(Some(id));
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
        self.touch(id, corpus)?;
        Ok(id)
    }
}

impl<I> Corpus for LibfuzzerCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    type Input = I;

    #[inline]
    fn count(&self) -> usize {
        self.mapping.enabled.map.len()
    }
    #[inline]
    fn count_disabled(&self) -> usize {
        self.mapping.disabled.map.len()
    }
    #[inline]
    fn count_all(&self) -> usize {
        self.count_disabled().saturating_add(self.count_disabled())
    }
    fn add(&mut self, testcase: Testcase<Self::Input>) -> Result<CorpusId, Error> {
        self._add(RefCell::new(testcase), false)
    }
    fn add_disabled(&mut self, testcase: Testcase<Self::Input>) -> Result<CorpusId, Error> {
        self._add(RefCell::new(testcase), true)
    }

    fn replace(
        &mut self,
        _id: CorpusId,
        _testcase: Testcase<Self::Input>,
    ) -> Result<Testcase<Self::Input>, Error> {
        unimplemented!("It is unsafe to use this corpus variant with replace!");
    }

    fn remove(&mut self, _id: CorpusId) -> Result<Testcase<Self::Input>, Error> {
        unimplemented!("It is unsafe to use this corpus variant with replace!");
    }

    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error> {
        self._get(id, &self.mapping.enabled)
    }

    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error> {
        match self._get(id, &self.mapping.enabled) {
            Ok(input) => Ok(input),
            Err(Error::KeyNotFound(..)) => return self._get(id, &self.mapping.disabled),
            Err(e) => Err(e),
        }
    }
    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.mapping.enabled.next(id)
    }
    fn peek_free_id(&self) -> CorpusId {
        self.mapping.peek_free_id()
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.mapping.enabled.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.mapping.enabled.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.mapping.enabled.last()
    }

    /// Get the nth corpus id; considers both enabled and disabled testcases
    #[inline]
    fn nth_from_all(&self, nth: usize) -> CorpusId {
        let enabled_count = self.count();
        if nth >= enabled_count {
            return self.mapping.disabled.keys[nth.saturating_sub(enabled_count)];
        }
        self.mapping.enabled.keys[nth]
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

impl<I> Corpus for ArtifactCorpus<I>
where
    I: Input + Serialize + for<'de> Deserialize<'de>,
{
    type Input = I;

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

    fn add_disabled(&mut self, _testcase: Testcase<Self::Input>) -> Result<CorpusId, Error> {
        unimplemented!("ArtifactCorpus disregards disabled inputs")
    }

    fn replace(
        &mut self,
        _id: CorpusId,
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
            .is_some_and(|last| last == id)
        {
            self.last.as_ref()
        } else {
            None
        };
        maybe_last.ok_or_else(|| Error::illegal_argument("Can only get the last corpus ID."))
    }

    fn peek_free_id(&self) -> CorpusId {
        CorpusId::from(self.count)
    }

    // This just calls Self::get as ArtifactCorpus disregards disabled entries
    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<Self::Input>>, Error> {
        self.get(id)
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

    fn load_input_into(&self, _testcase: &mut Testcase<Self::Input>) -> Result<(), Error> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }

    fn store_input_from(&self, _testcase: &Testcase<Self::Input>) -> Result<(), Error> {
        unimplemented!("Artifact prefix is thin and cannot get, replace, or remove.")
    }
}
