//! The null corpus does not store any [`Testcase`]s.
use core::{cell::RefCell, marker::PhantomData};

use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, Testcase},
    inputs::{Input, UsesInput},
    Error,
};

/// A corpus which does not store any [`Testcase`]s.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct NopCorpus<I> {
    empty: Option<CorpusId>,
    phantom: PhantomData<I>,
}

impl<I> UsesInput for NopCorpus<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> Corpus for NopCorpus<I>
where
    I: Input,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        0
    }

    /// Add an entry to the corpus and return its index
    #[inline]
    fn add(&mut self, _testcase: Testcase<I>) -> Result<CorpusId, Error> {
        Err(Error::unsupported("Unsupported by NopCorpus"))
    }

    /// Replaces the testcase at the given idx
    #[inline]
    fn replace(&mut self, _idx: CorpusId, _testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        Err(Error::unsupported("Unsupported by NopCorpus"))
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, _idx: CorpusId) -> Result<Testcase<I>, Error> {
        Err(Error::unsupported("Unsupported by NopCorpus"))
    }

    /// Get by id
    #[inline]
    fn get(&self, _idx: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        Err(Error::unsupported("Unsupported by NopCorpus"))
    }

    /// Current testcase scheduled
    #[inline]
    fn current(&self) -> &Option<CorpusId> {
        &self.empty
    }

    /// Current testcase scheduled (mutable)
    #[inline]
    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.empty
    }

    #[inline]
    fn next(&self, _idx: CorpusId) -> Option<CorpusId> {
        None
    }

    #[inline]
    fn prev(&self, _idx: CorpusId) -> Option<CorpusId> {
        None
    }

    #[inline]
    fn first(&self) -> Option<CorpusId> {
        None
    }

    #[inline]
    fn last(&self) -> Option<CorpusId> {
        None
    }

    #[inline]
    fn nth(&self, _nth: usize) -> CorpusId {
        CorpusId::from(0_usize)
    }

    #[inline]
    fn load_input_into(&self, _testcase: &mut Testcase<Self::Input>) -> Result<(), Error> {
        Err(Error::unsupported("Unsupported by NopCorpus"))
    }

    #[inline]
    fn store_input_from(&self, _testcase: &Testcase<Self::Input>) -> Result<(), Error> {
        Err(Error::unsupported("Unsupported by NopCorpus"))
    }
}

impl<I> NopCorpus<I>
where
    I: Input,
{
    /// Creates a new [`NopCorpus`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            empty: None,
            phantom: PhantomData {},
        }
    }
}
