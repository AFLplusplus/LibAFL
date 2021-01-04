pub mod testcase;
pub use testcase::Testcase;

use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;
use core::ptr;
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::path::PathBuf;

use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;

/// A way to obtain the containing testcase entries
pub trait HasTestcaseVec<I>
where
    I: Input,
{
    /// Get the entries vector field
    fn entries(&self) -> &[RefCell<Testcase<I>>];

    /// Get the entries vector field (mutable)
    fn entries_mut(&mut self) -> &mut Vec<RefCell<Testcase<I>>>;
}

/// Corpus with all current testcases
pub trait Corpus<I, R>: HasTestcaseVec<I> + serde::Serialize + serde::de::DeserializeOwned
where
    I: Input,
    R: Rand,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.entries().len()
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, testcase: Testcase<I>) -> usize {
        self.entries_mut().push(RefCell::new(testcase));
        self.entries().len() - 1
    }

    /// Replaces the testcase at the given idx
    fn replace(&mut self, idx: usize, testcase: Testcase<I>) -> Result<(), AflError> {
        if self.entries_mut().len() < idx {
            return Err(AflError::KeyNotFound(format!(
                "Index {} out of bounds",
                idx
            )));
        }
        self.entries_mut()[idx] = RefCell::new(testcase);
        Ok(())
    }

    /// Get by id
    #[inline]
    fn get(&self, idx: usize) -> &RefCell<Testcase<I>> {
        &self.entries()[idx]
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, entry: &Testcase<I>) -> Option<Testcase<I>> {
        match self
            .entries()
            .iter()
            .position(|x| ptr::eq(x.as_ptr(), entry))
        {
            Some(i) => Some(self.entries_mut().remove(i).into_inner()),
            None => None,
        }
    }

    /// Gets a random entry
    #[inline]
    fn random_entry(&self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), AflError> {
        if self.count() == 0 {
            Err(AflError::Empty("No entries in corpus".to_owned()))
        } else {
            let len = { self.entries().len() };
            let id = rand.below(len as u64) as usize;
            Ok((self.get(id), id))
        }
    }

    /// Returns the testcase for the given idx, with loaded input
    /*fn load_testcase(&mut self, idx: usize) -> Result<(), AflError> {
        let testcase = self.get(idx);
        // Ensure testcase is loaded
        match testcase.input() {
            None => {
                let new_testcase = match testcase.filename() {
                    Some(filename) => Testcase::load_from_disk(filename)?,
                    None => {
                        return Err(AflError::IllegalState(
                            "Neither input, nor filename specified for testcase".into(),
                        ))
                    }
                };

                self.replace(idx, new_testcase)?;
            }
            _ => (),
        }
        Ok(())
    }*/
    // TODO: IntoIter
    /// Gets the next entry
    fn next(&mut self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), AflError>;

    /// Returns the testacase we currently use
    fn current_testcase(&self) -> (&RefCell<Testcase<I>>, usize);
}

/// A corpus handling all important fuzzing in memory.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    entries: Vec<RefCell<Testcase<I>>>,
    pos: usize,
    phantom: PhantomData<R>,
}

impl<I, R> HasTestcaseVec<I> for InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    fn entries(&self) -> &[RefCell<Testcase<I>>] {
        &self.entries
    }
    fn entries_mut(&mut self) -> &mut Vec<RefCell<Testcase<I>>> {
        &mut self.entries
    }
}

impl<I, R> Corpus<I, R> for InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    /// Gets the next entry
    #[inline]
    fn next(&mut self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), AflError> {
        if self.count() == 0 {
            Err(AflError::Empty("No entries in corpus".to_owned()))
        } else {
            let len = { self.entries().len() };
            let id = rand.below(len as u64) as usize;
            self.pos = id;
            Ok((self.get(id), id))
        }
    }

    /// Returns the testacase we currently use
    #[inline]
    fn current_testcase(&self) -> (&RefCell<Testcase<I>>, usize) {
        (self.get(self.pos), self.pos)
    }
}

impl<I, R> InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    pub fn new() -> Self {
        Self {
            entries: vec![],
            pos: 0,
            phantom: PhantomData,
        }
    }
}

/// A corpus able to store testcases to dis, and load them from disk, when they are being used.
#[cfg(feature = "std")]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    entries: Vec<RefCell<Testcase<I>>>,
    dir_path: PathBuf,
    pos: usize,
    phantom: PhantomData<R>,
}

#[cfg(feature = "std")]
impl<I, R> HasTestcaseVec<I> for OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    #[inline]
    fn entries(&self) -> &[RefCell<Testcase<I>>] {
        &self.entries
    }
    #[inline]
    fn entries_mut(&mut self) -> &mut Vec<RefCell<Testcase<I>>> {
        &mut self.entries
    }
}

#[cfg(feature = "std")]
impl<I, R> Corpus<I, R> for OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    /// Add an entry and save it to disk
    fn add(&mut self, mut entry: Testcase<I>) -> usize {
        match entry.filename() {
            None => {
                // TODO walk entry metadatas to ask for pices of filename (e.g. :havoc in AFL)
                let filename = self.dir_path.join(format!("id_{}", &self.entries.len()));
                let filename_str = filename.to_str().expect("Invalid Path");
                entry.set_filename(filename_str.into());
            }
            _ => {}
        }
        self.entries.push(RefCell::new(entry));
        self.entries.len() - 1
    }

    #[inline]
    fn current_testcase(&self) -> (&RefCell<Testcase<I>>, usize) {
        (self.get(self.pos), self.pos)
    }

    /// Gets the next entry
    #[inline]
    fn next(&mut self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), AflError> {
        if self.count() == 0 {
            Err(AflError::Empty("No entries in corpus".to_owned()))
        } else {
            let len = { self.entries().len() };
            let id = rand.below(len as u64) as usize;
            self.pos = id;
            Ok((self.get(id), id))
        }
    }

    // TODO save and remove files, cache, etc..., ATM use just InMemoryCorpus
}

#[cfg(feature = "std")]
impl<I, R> OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    pub fn new(dir_path: PathBuf) -> Self {
        Self {
            dir_path: dir_path,
            entries: vec![],
            pos: 0,
            phantom: PhantomData,
        }
    }
}

/// A Queue-like corpus, wrapping an existing Corpus instance
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct QueueCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    corpus: C,
    pos: usize,
    cycles: u64,
    phantom: PhantomData<(I, R)>,
}

impl<C, I, R> HasTestcaseVec<I> for QueueCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    #[inline]
    fn entries(&self) -> &[RefCell<Testcase<I>>] {
        self.corpus.entries()
    }
    #[inline]
    fn entries_mut(&mut self) -> &mut Vec<RefCell<Testcase<I>>> {
        self.corpus.entries_mut()
    }
}

impl<C, I, R> Corpus<I, R> for QueueCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.corpus.count()
    }

    #[inline]
    fn add(&mut self, entry: Testcase<I>) -> usize {
        self.corpus.add(entry)
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, entry: &Testcase<I>) -> Option<Testcase<I>> {
        self.corpus.remove(entry)
    }

    /// Gets a random entry
    #[inline]
    fn random_entry(&self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), AflError> {
        self.corpus.random_entry(rand)
    }

    /// Returns the testacase we currently use
    #[inline]
    fn current_testcase(&self) -> (&RefCell<Testcase<I>>, usize) {
        (self.get(self.pos - 1), self.pos - 1)
    }

    /// Gets the next entry
    #[inline]
    fn next(&mut self, _rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), AflError> {
        self.pos += 1;
        if self.corpus.count() == 0 {
            return Err(AflError::Empty("Corpus".to_owned()));
        }
        if self.pos > self.corpus.count() {
            // TODO: Always loop or return informational error?
            self.pos = 1;
            self.cycles += 1;
        }
        Ok((&self.corpus.entries()[self.pos - 1], self.pos - 1))
    }
}

impl<C, I, R> QueueCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    pub fn new(corpus: C) -> Self {
        Self {
            corpus: corpus,
            phantom: PhantomData,
            cycles: 0,
            pos: 0,
        }
    }

    #[inline]
    pub fn cycles(&self) -> u64 {
        self.cycles
    }

    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use crate::corpus::Corpus;
    use crate::corpus::Testcase;
    use crate::corpus::{OnDiskCorpus, QueueCorpus};
    use crate::inputs::bytes::BytesInput;
    use crate::utils::StdRand;

    use std::path::PathBuf;

    #[test]
    fn test_queuecorpus() {
        let mut rand = StdRand::new(0);
        let mut q = QueueCorpus::new(OnDiskCorpus::<BytesInput, StdRand>::new(PathBuf::from(
            "fancy/path",
        )));
        let t = Testcase::with_filename(BytesInput::new(vec![0 as u8; 4]), "fancyfile".into());
        q.add(t);
        let filename = q
            .next(&mut rand)
            .unwrap()
            .0
            .borrow()
            .filename()
            .as_ref()
            .unwrap()
            .to_owned();
        assert_eq!(
            filename,
            q.next(&mut rand)
                .unwrap()
                .0
                .borrow()
                .filename()
                .as_ref()
                .unwrap()
                .to_owned()
        );
        assert_eq!(filename, "fancyfile");
    }
}
