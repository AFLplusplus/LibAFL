use alloc::{borrow::ToOwned, vec::Vec};
use core::{cell::RefCell, marker::PhantomData};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::Corpus, corpus::HasTestcaseVec, corpus::Testcase, inputs::Input, utils::Rand, AflError,
};

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
