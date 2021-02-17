//! The queue corpus implements an afl-like queue mechanism

use alloc::{borrow::ToOwned, vec::Vec};
use core::{cell::RefCell, marker::PhantomData};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::Corpus, corpus::HasTestcaseVec, corpus::Testcase, inputs::Input, utils::Rand, Error,
};

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
    fn random_entry(&self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), Error> {
        self.corpus.random_entry(rand)
    }

    /// Returns the testacase we currently use
    #[inline]
    fn current_testcase(&self) -> (&RefCell<Testcase<I>>, usize) {
        (self.get(self.pos - 1), self.pos - 1)
    }

    /// Gets the next entry
    #[inline]
    fn next(&mut self, _rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), Error> {
        self.pos += 1;
        if self.corpus.count() == 0 {
            return Err(Error::Empty("Corpus".to_owned()));
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
    
    // TODO maybe impl HasCorpus
    #[inline]
    pub fn corpus(&self) -> &C {
        &self.corpus
    }
    
    #[inline]
    pub fn corpus_mut(&mut self) -> &mut C {
        &mut self.corpus
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {

    use std::path::PathBuf;

    use crate::{
        corpus::{Corpus, OnDiskCorpus, QueueCorpus, Testcase},
        inputs::bytes::BytesInput,
        utils::StdRand,
    };

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
