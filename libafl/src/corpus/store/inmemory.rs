use core::{cell::RefCell, marker::PhantomData};
use std::rc::Rc;

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use super::{InMemoryCorpusMap, Store};
use crate::corpus::{CorpusId, Testcase};

/// The map type in which testcases are stored (disable the feature `corpus_btreemap` to use a `HashMap` instead of `BTreeMap`)
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct InMemoryStore<I, M> {
    enabled_map: M,
    disabled_map: M,
    phantom: PhantomData<I>,
}

impl<I, M> Store<I> for InMemoryStore<I, M>
where
    M: InMemoryCorpusMap<Testcase<I>>,
{
    fn count(&self) -> usize {
        self.enabled_map.count()
    }

    fn count_disabled(&self) -> usize {
        self.disabled_map.count()
    }

    fn is_empty(&self) -> bool {
        self.enabled_map.is_empty()
    }

    fn add(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<(), Error> {
        Ok(self.enabled_map.add(id, testcase))
    }

    fn add_disabled(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<(), Error> {
        Ok(self.disabled_map.add(id, testcase))
    }

    fn replace(&mut self, id: CorpusId, new_testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        self.enabled_map.replace(id, new_testcase).ok_or_else(|| {
            Error::key_not_found(format!("Index {id} not found, could not replace."))
        })
    }

    fn remove(&mut self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        let mut testcase = self.enabled_map.remove(id);

        if testcase.is_none() {
            testcase = self.disabled_map.remove(id);
        }

        testcase
            .map(|x| x.clone())
            .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))
    }

    fn get(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.enabled_map
            .get(id)
            .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))
    }

    fn get_from_all(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        let mut testcase = self.enabled_map.get(id);

        if testcase.is_none() {
            testcase = self.disabled_map.get(id);
        }

        testcase.ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.enabled_map.prev(id)
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.enabled_map.next(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.enabled_map.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.enabled_map.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.enabled_map.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        let nb_enabled = self.enabled_map.count();
        if nth >= nb_enabled {
            self.disabled_map.nth(nth.saturating_sub(nb_enabled))
        } else {
            self.enabled_map.nth(nth)
        }
    }
}
