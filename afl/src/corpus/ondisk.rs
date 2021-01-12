use alloc::vec::Vec;
use core::{cell::RefCell, marker::PhantomData};
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::path::PathBuf;

use crate::{
    corpus::Corpus, corpus::HasTestcaseVec, corpus::Testcase, inputs::Input, utils::Rand, AflError,
};

/// A corpus able to store testcases to disk, and load them from disk, when they are being used.
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
