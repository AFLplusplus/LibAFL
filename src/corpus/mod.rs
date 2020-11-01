pub mod testcase;
pub use testcase::Testcase;

use crate::utils::{Rand, HasRand};
use crate::inputs::Input;
use crate::AflError;

use std::path::PathBuf;

pub trait HasEntriesVec<InputT: Input> {
    /// Get the entries vector field
    fn entries(&self) -> &Vec<Box<Testcase<InputT>>>;

    /// Get the entries vector field (mutable)
    fn entries_mut(&mut self) -> &mut Vec<Box<Testcase<InputT>>>;
}

/// Corpus with all current testcases
pub trait Corpus<InputT: Input, RandT: Rand> : HasEntriesVec<InputT> + HasRand<RandT> {
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.entries().len()
    }

    /// Add an entry to the corpus
    fn add(&mut self, mut entry: Box<Testcase<InputT>>) {
        self.entries_mut().push(entry);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &Testcase<InputT>) -> Option<Box<Testcase<InputT>>> {
        let mut i: usize = 0;
        let mut found = false;
        for x in self.entries() {
            i = i + 1;
            if x.as_ref() as *const _ == entry as *const _ {
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
        Some(self.entries_mut().remove(i))
    }

    /// Gets a random entry
    fn random_entry(&mut self) -> Result<&Box<Testcase<InputT>>, AflError> {
        let id = self.rand_mut().below(self.entries().len() as u64) as usize;
        Ok(self.entries_mut().get_mut(id).unwrap())
    }

    /// Gets the next entry (random by default)
    fn get(&mut self) -> Result<&Box<Testcase<InputT>>, AflError> {
        self.random_entry()
    }
}

pub struct InMemoryCorpus<'a, InputT: Input, RandT: Rand> {
    rand: &'a mut RandT,
    entries: Vec<Box<Testcase<InputT>>>,
}

impl<InputT: Input, RandT: Rand> HasEntriesVec<InputT> for InMemoryCorpus<'_, InputT, RandT> {
    fn entries(&self) -> &Vec<Box<Testcase<InputT>>> {
        &self.entries
    }
    fn entries_mut(&mut self) -> &mut Vec<Box<Testcase<InputT>>>{
        &mut self.entries
    }
}

impl<InputT: Input, RandT: Rand> HasRand<RandT> for InMemoryCorpus<'_, InputT, RandT> {
    fn rand(&self) -> &Box<dyn Rand> {
        &self.rand
    }
    fn rand_mut(&mut self) -> &mut Box<dyn Rand> {
        &mut self.rand
    }
}

impl<InputT: Input, RandT: Rand> Corpus<InputT, RandT> for InMemoryCorpus<'_, InputT, RandT> {
    // Just use the default implementation
}

impl<InputT: Input, RandT: Rand> InMemoryCorpus<'_, InputT, RandT> {
    pub fn new<'a>(rand: &'a mut RandT) -> Self {
        InMemoryCorpus {
            rand: rand,
            entries: vec![],
        }
    }
}

pub struct OnDiskCorpus<'a, InputT: Input, RandT: Rand> {
    rand: &'a mut RandT,
    entries: Vec<Box<Testcase<InputT>>>,
    dir_path: PathBuf,
}

impl<InputT: Input, RandT: Rand> HasEntriesVec<InputT> for OnDiskCorpus<'_, InputT, RandT> {
    fn entries(&self) -> &Vec<Box<Testcase<InputT>>> {
        &self.entries
    }
    fn entries_mut(&mut self) -> &mut Vec<Box<Testcase<InputT>>>{
        &mut self.entries
    }
}

impl<InputT: Input, RandT: Rand> HasRand<RandT> for OnDiskCorpus<'_, InputT, RandT> {
    fn rand(&self) -> &Box<dyn Rand> {
        &self.rand
    }
    fn rand_mut(&mut self) -> &mut Box<dyn Rand> {
        &mut self.rand
    }
}

impl<InputT: Input, RandT: Rand> Corpus<InputT, RandT> for OnDiskCorpus<'_, InputT, RandT> {
    /// Add an entry and save it to disk
    fn add(&mut self, mut entry: Box<Testcase<InputT>>) {
        if entry.filename() == None {
            // TODO walk entry metadatas to ask for pices of filename (e.g. :havoc in AFL)
            let filename = &(String::from("id:") + &self.entries.len().to_string());
            let filename = self.dir_path.join(filename);
            entry.filename_mut() = filename;
        }
        self.entries.push(entry);
    }

    // TODO save and remove files, cache, etc..., ATM use just InMemoryCorpus
}

impl<InputT: Input, RandT: Rand> OnDiskCorpus<'_, InputT, RandT> {
    pub fn new<'a>(rand: &'a mut RandT, dir_path: PathBuf) -> Self {
        OnDiskCorpus {
            dir_path: dir_path,
            entries: vec![],
            rand: rand,
        }
    }
}

/// A Queue-like corpus, wrapping an existing Corpus instance
pub struct QueueCorpus<'a, InputT: Input, RandT: Rand, CorpusT: Corpus<InputT, RandT>> {
    corpus: CorpusT,
    pos: usize,
    cycles: u64,
}

impl<'a, InputT: Input, RandT: Rand, CorpusT: Corpus<InputT, RandT>> Corpus<InputT, RandT> for QueueCorpus<'_, InputT, RandT, CorpusT> {
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.corpus.count()
    }

    fn add(&mut self, entry: Box<Testcase<InputT>>) {
        self.corpus.add(entry);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &Testcase<InputT>) -> Option<Box<Testcase<InputT>>> {
        self.corpus.remove(entry)
    }

    /// Gets a random entry
    fn random_entry(&mut self) -> Result<&Box<Testcase<InputT>>, AflError> {
        self.corpus.random_entry()
    }

    /// Gets the next entry
    fn get(&mut self) -> Result<&Box<Testcase<InputT>>, AflError> {
        if self.count() == 0 {
            return Err(AflError::Empty("Testcases".to_string()));
        }
        self.pos = self.pos + 1;
        if self.pos >= self.count() {
            self.cycles = self.cycles + 1;
            self.pos = 0;
        }
        Ok(self.corpus.entries.get_mut(self.pos).unwrap())
    }
}

impl<'a, InputT: Input, RandT: Rand, CorpusT: Corpus<InputT, RandT>> QueueCorpus<'_, InputT, RandT, CorpusT> {
    pub fn new(corpus: CorpusT) -> Self {
        QueueCorpus {
            corpus: corpus,
            cycles: 0,
            pos: 0,
        }
    }

    pub fn cycles(&self) -> u64 {
        self.cycles
    }

    pub fn pos(&self) -> usize {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use crate::corpus::Corpus;
    use crate::corpus::{QueueCorpus, OnDiskCorpus};
    use crate::corpus::Testcase;
    use crate::inputs::bytes::BytesInput;
    use crate::utils::Xoshiro256StarRand;

    use std::path::PathBuf;

    #[test]

    fn test_queuecorpus() {
        let mut rand = Xoshiro256StarRand::new();
        let mut q = QueueCorpus::new(OnDiskCorpus::new(&mut rand, PathBuf::from("fancy/path")));
        let i = Box::new(BytesInput::new(vec![0; 4]));
        let mut t = Box::new(Testcase::new(i));
        t.set_filename(PathBuf::from("fancyfile"));
        q.add(t);
        let filename = q.get().unwrap().get_filename().unwrap().to_owned();
        assert_eq!(filename, q.get().unwrap().get_filename().unwrap().to_owned());
        assert_eq!(filename, PathBuf::from("fancy/path/fancyfile"));
    }
}
