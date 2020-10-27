use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;
use hashbrown::HashMap;
use std::fmt::Debug;

pub trait TestcaseMetadata: Debug {}

pub trait Testcase: Debug {
    fn load_input(&mut self) -> Result<&Box<dyn Input>, AflError>;
    fn is_on_disk(&self) -> bool;
    fn get_filename(&self) -> &str;
    fn get_metadatas(&mut self) -> &mut HashMap<String, Box<dyn TestcaseMetadata>>;
}

/// Corpus with all current testcases
pub trait Corpus: Debug {
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

/// A queue-like corpus
pub trait Queue: Corpus {
    fn get_cycles(&self) -> u64;

    fn get_pos(&self) -> usize;
}

#[derive(Debug)]
pub struct DefaultQueue<'a> {
    rand: &'a mut dyn Rand,
    pos: usize,
    cycles: u64,
    entries: Vec<Box<dyn Testcase>>,
    dir_path: String,
}

impl Corpus for DefaultQueue<'_> {
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.entries.len()
    }

    fn add(&mut self, entry: Box<dyn Testcase>) {
        self.entries.push(entry);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &dyn Testcase) -> Option<Box<dyn Testcase>> {
        let mut i: usize = 0;
        let mut found = false;
        for x in &self.entries {
            i = i + 1;
            if x.as_ref().get_filename() == entry.get_filename() {
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
        if self.entries.len() == 0 {
            return Err(AflError::Unknown);
        }
        self.pos = self.pos + 1;
        if self.pos >= self.entries.len() {
            self.cycles = self.cycles + 1;
            self.pos = 0;
        }
        Ok(self.entries.get_mut(self.pos).unwrap())
    }
}

impl Queue for DefaultQueue<'_> {
    fn get_cycles(&self) -> u64 {
        self.cycles
    }

    fn get_pos(&self) -> usize {
        self.pos
    }
}

impl DefaultQueue<'_> {
    pub fn new<'a>(rand: &'a mut dyn Rand, dir_path: &str) -> DefaultQueue<'a> {
        DefaultQueue {
            cycles: 0,
            dir_path: dir_path.to_owned(),
            entries: vec![],
            pos: 0,
            rand: rand,
        }
    }
}

#[derive(Debug, Default)]
struct SimpleTestcase {
    is_on_disk: bool,
    filename: String,
    metadatas: HashMap<String, Box<dyn TestcaseMetadata>>,
}

impl Testcase for SimpleTestcase {
    fn load_input(&mut self) -> Result<&Box<dyn Input>, AflError> {
        // TODO: Implement
        Err(AflError::Unknown)
    }

    fn is_on_disk(&self) -> bool {
        self.is_on_disk
    }

    fn get_filename(&self) -> &str {
        &self.filename
    }

    fn get_metadatas(&mut self) -> &mut HashMap<String, Box<dyn TestcaseMetadata>> {
        &mut self.metadatas
    }
}

impl SimpleTestcase {
    fn new(filename: &str) -> Self {
        SimpleTestcase {
            filename: filename.to_owned(),
            is_on_disk: false,
            metadatas: HashMap::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::corpus::Corpus;
    use crate::corpus::DefaultQueue;
    use crate::corpus::SimpleTestcase;
    use crate::utils::Xoshiro256StarRand;

    #[test]
    fn test_defaultqueue() {
        let mut rand = Xoshiro256StarRand::new();
        let mut q = DefaultQueue::new(&mut rand, "fancy/path");
        q.add(Box::new(SimpleTestcase::new("fancyfile")));
        let filename = q.get().unwrap().get_filename().to_owned();
        assert_eq!(filename, q.get().unwrap().get_filename());
        assert_eq!(filename, "fancyfile");
    }
}
