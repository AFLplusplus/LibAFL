//! Dynamic corpus that allows users to switch corpus types at runtime.
use std::{cell::RefCell, marker::PhantomData};

use libafl_bolts::Error;

use crate::corpus::{Corpus, CorpusId, Testcase};

/// An dynamic corpus type accepting two types of corpus at runtime. This helps rustc better
/// reason about the bounds compared to dyn objects.
#[derive(Debug)]
pub enum DynamicCorpus<C1, C2, I> {
    /// Corpus1 implementation
    Corpus1(C1, PhantomData<I>),
    /// Corpus2 implementation
    Corpus2(C2, PhantomData<I>),
}

/// A helper macro to avoid too many duplicates.
macro_rules! select_corpus {
    ($sf: tt, $it: tt, $( $args: tt), *) => {
        match $sf {
            Self::Corpus1(c1, _) => c1.$it( $($args),* ),
            Self::Corpus2(c2, _) => c2.$it( $($args),* ),
        }
    };
}

impl<C1, C2, I> DynamicCorpus<C1, C2, I> {
    /// Create a `DynamicCorpus` with Corpus1 variant.
    pub fn corpus1(c: C1) -> Self {
        Self::Corpus1(c, PhantomData)
    }

    /// Create a `DynamicCorpus` with Corpus2 variant.
    pub fn corpus2(c: C2) -> Self {
        Self::Corpus2(c, PhantomData)
    }
}

impl<C1, C2, I> Corpus<I> for DynamicCorpus<C1, C2, I>
where
    C1: Corpus<I>,
    C2: Corpus<I>,
{
    fn peek_free_id(&self) -> CorpusId {
        select_corpus!(self, peek_free_id,)
    }

    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        select_corpus!(self, add, testcase)
    }

    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        select_corpus!(self, add_disabled, testcase)
    }

    fn cloned_input_for_id(&self, idx: CorpusId) -> Result<I, Error>
    where
        I: Clone,
    {
        select_corpus!(self, cloned_input_for_id, idx)
    }

    fn count(&self) -> usize {
        select_corpus!(self, count,)
    }

    fn count_all(&self) -> usize {
        select_corpus!(self, count_all,)
    }

    fn count_disabled(&self) -> usize {
        select_corpus!(self, count_disabled,)
    }

    fn current(&self) -> &Option<CorpusId> {
        select_corpus!(self, current,)
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        select_corpus!(self, current_mut,)
    }

    fn first(&self) -> Option<CorpusId> {
        select_corpus!(self, first,)
    }

    fn get(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        select_corpus!(self, get, id)
    }

    fn get_from_all(&self, id: CorpusId) -> Result<&RefCell<Testcase<I>>, Error> {
        select_corpus!(self, get_from_all, id)
    }

    fn is_empty(&self) -> bool {
        select_corpus!(self, is_empty,)
    }

    fn last(&self) -> Option<CorpusId> {
        select_corpus!(self, last,)
    }

    fn load_input_into(&self, testcase: &mut Testcase<I>) -> Result<(), Error> {
        select_corpus!(self, load_input_into, testcase)
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        select_corpus!(self, next, id)
    }

    fn nth(&self, nth: usize) -> CorpusId {
        select_corpus!(self, nth, nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        select_corpus!(self, nth_from_all, nth)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        select_corpus!(self, prev, id)
    }

    fn remove(&mut self, id: CorpusId) -> Result<Testcase<I>, Error> {
        select_corpus!(self, remove, id)
    }

    fn replace(&mut self, idx: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        select_corpus!(self, replace, idx, testcase)
    }

    fn store_input_from(&self, testcase: &Testcase<I>) -> Result<(), Error> {
        select_corpus!(self, store_input_from, testcase)
    }
}
