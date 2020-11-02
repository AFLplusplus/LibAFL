pub mod testcase;
pub use testcase::Testcase;

use crate::utils::{Rand, HasRand};
use crate::inputs::Input;
use crate::AflError;

use std::path::PathBuf;
use std::marker::PhantomData;

pub trait HasEntriesVec<I> where I: Input {
    /// Get the entries vector field
    fn entries(&self) -> &Vec<Box<Testcase<I>>>;

    /// Get the entries vector field (mutable)
    fn entries_mut(&mut self) -> &mut Vec<Box<Testcase<I>>>;
}

/// Corpus with all current testcases
pub trait Corpus<I> : HasEntriesVec<I> + HasRand where I: Input {
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.entries().len()
    }

    /// Add an entry to the corpus
    fn add(&mut self, mut entry: Box<Testcase<I>>) {
        self.entries_mut().push(entry);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &Testcase<I>) -> Option<Box<Testcase<I>>> {
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
    fn random_entry(&mut self) -> Result<&Box<Testcase<I>>, AflError> {
        let len = { self.entries().len() };
        let id = self.rand_mut().below(len as u64) as usize;
        Ok(self.entries_mut().get_mut(id).unwrap())
    }

    /// Gets the next entry (random by default)
    fn get(&mut self) -> Result<&Box<Testcase<I>>, AflError> {
        self.random_entry()
    }
}

pub struct InMemoryCorpus<'a, I, R> where I: Input, R: Rand {
    rand: &'a mut R,
    entries: Vec<Box<Testcase<I>>>
}

impl<I, R> HasEntriesVec<I> for InMemoryCorpus<'_, I, R> where I: Input, R: Rand {
    fn entries(&self) -> &Vec<Box<Testcase<I>>> {
        &self.entries
    }
    fn entries_mut(&mut self) -> &mut Vec<Box<Testcase<I>>>{
        &mut self.entries
    }
}

impl<I, R> HasRand for InMemoryCorpus<'_, I, R> where I: Input, R: Rand {
    type R = R;

    fn rand(&self) -> &Self::R {
        &self.rand
    }
    fn rand_mut(&mut self) -> &mut Self::R {
        &mut self.rand
    }
}

impl<I, R> Corpus<I> for InMemoryCorpus<'_, I, R> where I: Input, R: Rand {
    // Just use the default implementation
}

impl<'a, I, R> InMemoryCorpus<'a, I, R> where I: Input, R: Rand {
    pub fn new(rand: &'a mut R) -> Self {
        InMemoryCorpus {
            rand: rand,
            entries: vec![],
        }
    }
}

pub struct OnDiskCorpus<'a, I, R> where I: Input, R: Rand {
    rand: &'a mut R,
    entries: Vec<Box<Testcase<I>>>,
    dir_path: PathBuf,
}

impl<I, R> HasEntriesVec<I> for OnDiskCorpus<'_, I, R> where I: Input, R: Rand {
    fn entries(&self) -> &Vec<Box<Testcase<I>>> {
        &self.entries
    }
    fn entries_mut(&mut self) -> &mut Vec<Box<Testcase<I>>>{
        &mut self.entries
    }
}

impl<I, R> HasRand for OnDiskCorpus<'_, I, R> where I: Input, R: Rand {
    type R = R;

    fn rand(&self) -> &Self::R {
        &self.rand
    }
    fn rand_mut(&mut self) -> &mut Self::R {
        &mut self.rand
    }
}

impl<I, R> Corpus<I> for OnDiskCorpus<'_, I, R> where I: Input, R: Rand {
    /// Add an entry and save it to disk
    fn add(&mut self, mut entry: Box<Testcase<I>>) {
        if *entry.filename() == None {
            // TODO walk entry metadatas to ask for pices of filename (e.g. :havoc in AFL)
            let filename = &(String::from("id:") + &self.entries.len().to_string());
            let filename = self.dir_path.join(filename);
            *entry.filename_mut() = Some(filename);
        }
        self.entries.push(entry);
    }

    // TODO save and remove files, cache, etc..., ATM use just InMemoryCorpus
}

impl<'a, I, R> OnDiskCorpus<'a, I, R> where I: Input, R: Rand {
    pub fn new(rand: &'a mut R, dir_path: PathBuf) -> Self {
        OnDiskCorpus {
            dir_path: dir_path,
            entries: vec![],
            rand: rand,
        }
    }
}

/// A Queue-like corpus, wrapping an existing Corpus instance
pub struct QueueCorpus<I, C> where I: Input, C: Corpus<I> {
    corpus: C,
    phantom: PhantomData<I>,
    pos: usize,
    cycles: u64,
}

impl<'a, I, C> HasEntriesVec<I> for QueueCorpus<I, C> where I: Input, C: Corpus<I> {
    fn entries(&self) -> &Vec<Box<Testcase<I>>> {
        self.corpus.entries()
    }
    fn entries_mut(&mut self) -> &mut Vec<Box<Testcase<I>>>{
        self.corpus.entries_mut()
    }
}

impl<'a, I, C> HasRand for QueueCorpus<I, C> where I: Input, C: Corpus<I> {
    type R = C::R;

    fn rand(&self) -> &Self::R {
        self.corpus.rand()
    }
    fn rand_mut(&mut self) -> &mut Self::R {
        self.corpus.rand_mut()
    }
}

impl<'a, I, C> Corpus<I> for QueueCorpus<I, C> where I: Input, C: Corpus<I> {
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.corpus.count()
    }

    fn add(&mut self, entry: Box<Testcase<I>>) {
        self.corpus.add(entry);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &Testcase<I>) -> Option<Box<Testcase<I>>> {
        self.corpus.remove(entry)
    }

    /// Gets a random entry
    fn random_entry(&mut self) -> Result<&Box<Testcase<I>>, AflError> {
        self.corpus.random_entry()
    }

    /// Gets the next entry
    fn get(&mut self) -> Result<&Box<Testcase<I>>, AflError> {
        if self.corpus.count() == 0 {
            return Err(AflError::Empty("Testcases".to_string()));
        }
        self.pos = self.pos + 1;
        if self.pos >= self.corpus.count() {
            self.cycles = self.cycles + 1;
            self.pos = 0;
        }
        Ok(self.corpus.entries_mut().get_mut(self.pos).unwrap())
    }
}

impl<'a, I, C> QueueCorpus<I, C> where I: Input, C: Corpus<I> {
    pub fn new(corpus: C) -> Self {
        QueueCorpus::<I, C> {
            corpus: corpus,
            phantom: PhantomData,
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
        *t.filename_mut() = Some(PathBuf::from("fancyfile"));
        q.add(t);
        let filename = q.get().unwrap().filename().as_ref().unwrap().to_owned();
        assert_eq!(filename, q.get().unwrap().filename().as_ref().unwrap().to_owned());
        assert_eq!(filename, PathBuf::from("fancy/path/fancyfile"));
    }
}
