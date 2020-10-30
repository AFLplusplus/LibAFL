pub mod testcase;
pub use testcase::{Testcase, SimpleTestcase};

use crate::utils::Rand;
use crate::AflError;

use std::path::PathBuf;

/// Corpus with all current testcases
pub trait Corpus {
    /// Returns the number of elements
    fn count(&self) -> usize;

    fn add(&mut self, entry: Box<dyn Testcase>);

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &dyn Testcase) -> Option<Box<dyn Testcase>>;

    /// Gets a random entry
    fn random_entry(&mut self) -> Result<&Box<dyn Testcase>, AflError>;

    /// Gets the next entry
    fn get(&mut self) -> Result<&Box<dyn Testcase>, AflError>;
}

pub struct BaseCorpus<'a, RandT: Rand> {
    rand: &'a mut RandT,
    entries: Vec<Box<dyn Testcase>>,
    dir_path: PathBuf,
}

impl<RandT: Rand> Corpus for BaseCorpus<'_, RandT> {
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.entries.len()
    }

    fn add(&mut self, mut entry: Box<dyn Testcase>) {
        if entry.get_filename() == None {
            // TODO walk entry metadatas to ask for pices of filename (e.g. :havoc in AFL)
            let filename = &(String::from("id:") + &self.entries.len().to_string());
            let filename = self.dir_path.join(filename);
            entry.set_filename(filename);
        }
        self.entries.push(entry);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &dyn Testcase) -> Option<Box<dyn Testcase>> {
        let mut i: usize = 0;
        let mut found = false;
        for x in &self.entries {
            i = i + 1;
            if x.as_ref() as *const _ == entry as *const _ {
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
        Some(self.entries.remove(i))
    }

    /// Gets a random entry
    fn random_entry(&mut self) -> Result<&Box<dyn Testcase>, AflError> {
        let id = self.rand.below(self.entries.len() as u64) as usize;
        Ok(self.entries.get_mut(id).unwrap())
    }

    /// Gets the next entry
    fn get(&mut self) -> Result<&Box<dyn Testcase>, AflError> {
        self.random_entry()
    }
}

impl<RandT: Rand> BaseCorpus<'_, RandT> {
    pub fn new<'a>(rand: &'a mut RandT, dir_path: PathBuf) -> BaseCorpus<'a, RandT> {
        BaseCorpus {
            dir_path: dir_path,
            entries: vec![],
            rand: rand,
        }
    }
}

/// A queue-like corpus
pub struct QueueCorpus<'a, RandT: Rand> {
    base: BaseCorpus<'a, RandT>,
    pos: usize,
    cycles: u64,
}

impl<RandT: Rand> Corpus for QueueCorpus<'_, RandT> {
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.base.count()
    }

    fn add(&mut self, entry: Box<dyn Testcase>) {
        self.base.add(entry);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &dyn Testcase) -> Option<Box<dyn Testcase>> {
        self.base.remove(entry)
    }

    /// Gets a random entry
    fn random_entry(&mut self) -> Result<&Box<dyn Testcase>, AflError> {
        self.base.random_entry()
    }

    /// Gets the next entry
    fn get(&mut self) -> Result<&Box<dyn Testcase>, AflError> {
        if self.count() == 0 {
            return Err(AflError::Empty("Testcases".to_string()));
        }
        self.pos = self.pos + 1;
        if self.pos >= self.count() {
            self.cycles = self.cycles + 1;
            self.pos = 0;
        }
        Ok(self.base.entries.get_mut(self.pos).unwrap())
    }
}

impl<RandT: Rand> QueueCorpus<'_, RandT> {
    pub fn new<'a>(rand: &'a mut RandT, dir_path: PathBuf) -> QueueCorpus<'a, RandT> {
        QueueCorpus {
            base: BaseCorpus::new(rand, dir_path),
            cycles: 0,
            pos: 0,
        }
    }

    pub fn get_cycles(&self) -> u64 {
        self.cycles
    }

    pub fn get_pos(&self) -> usize {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use crate::corpus::Corpus;
    use crate::corpus::QueueCorpus;
    use crate::corpus::SimpleTestcase;
    use crate::corpus::Testcase;
    use crate::inputs::bytes::BytesInput;
    use crate::utils::Xoshiro256StarRand;

    use std::path::PathBuf;

    #[test]

    fn test_queuecorpus() {
        let mut rand = Xoshiro256StarRand::new();
        let mut q = QueueCorpus::new(&mut rand, PathBuf::from("fancy/path"));
        let i = Box::new(BytesInput::new(vec![0; 4]));
        let mut t = Box::new(SimpleTestcase::new(i));
        t.set_filename(PathBuf::from("fancyfile"));
        q.add(t);
        let filename = q.get().unwrap().get_filename().unwrap().to_owned();
        assert_eq!(filename, q.get().unwrap().get_filename().unwrap().to_owned());
        assert_eq!(filename, PathBuf::from("fancyfile"));
    }
}
