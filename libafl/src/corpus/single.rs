use core::{cell::RefCell, marker::PhantomData};
use std::{rc::Rc, vec::Vec};

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use super::{Corpus, CorpusCounter, CorpusId, Testcase, store::Store};

/// You average corpus.
/// It has one backing store, used to store / retrieve testcases.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct SingleCorpus<I, S> {
    /// The backing testcase store
    store: S,
    /// The corpus ID counter
    counter: CorpusCounter,
    /// The keys in order (use `Vec::binary_search`)
    keys: Vec<CorpusId>,
    /// The current ID
    current: Option<CorpusId>,
    phantom: PhantomData<I>,
}

impl<I, S> SingleCorpus<I, S>
where
    S: Default,
{
    pub fn new() -> Self {
        Self {
            store: S::default(),
            counter: CorpusCounter::default(),
            keys: Vec::new(),
            current: None,
            phantom: PhantomData,
        }
    }
}

impl<I, S> Corpus<I> for SingleCorpus<I, S>
where
    S: Store<I>,
{
    fn count(&self) -> usize {
        self.store.count()
    }

    fn count_disabled(&self) -> usize {
        self.store.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.store.count_all()
    }

    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        let new_id = self.counter.new_id();
        self.store.add(new_id, testcase)?;
        Ok(new_id)
    }

    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        let new_id = self.counter.new_id();
        self.store.add_disabled(new_id, testcase)?;
        Ok(new_id)
    }

    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        self.store.replace(id, testcase)
    }

    fn remove(&mut self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.store.remove(id)
    }

    fn get(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.store.get(id)
    }

    fn get_from_all(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.store.get_from_all(id)
    }

    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.store.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.store.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.store.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.store.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.store.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.store.nth_from_all(nth)
    }
}
