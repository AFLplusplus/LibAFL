//! Multiple map implementations for the in-memory store.

use core::cell::RefCell;
use std::{collections::BTreeMap, rc::Rc, vec::Vec};

use num_traits::Zero;
use serde::{Deserialize, Serialize};

use crate::corpus::CorpusId;

pub trait InMemoryCorpusMap<T> {
    /// Returns the number of testcases
    fn count(&self) -> usize;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count().is_zero()
    }

    /// Store the testcase associated to corpus_id.
    fn add(&mut self, id: CorpusId, testcase: T);

    /// Replaces the [`Testcase`] at the given idx, returning the existing.
    fn replace(&mut self, id: CorpusId, new_testcase: T) -> Option<T>;

    /// Removes an entry from the corpus, returning it if it was present; considers both enabled and disabled testcases
    fn remove(&mut self, id: CorpusId) -> Option<Rc<RefCell<T>>>;

    /// Get by id; considers only enabled testcases
    fn get(&self, id: CorpusId) -> Option<Rc<RefCell<T>>>;

    /// Get the prev corpus id in chronological order
    fn prev(&self, id: CorpusId) -> Option<CorpusId>;

    /// Get the next corpus id in chronological order
    fn next(&self, id: CorpusId) -> Option<CorpusId>;

    /// Get the first inserted corpus id
    fn first(&self) -> Option<CorpusId>;

    /// Get the last inserted corpus id
    fn last(&self) -> Option<CorpusId>;

    /// Get the nth inserted item
    fn nth(&self, nth: usize) -> CorpusId;
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct CorpusIdHistory {
    keys: Vec<CorpusId>,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct BtreeCorpusMap<T> {
    /// A map of `CorpusId` to `Testcase`.
    map: BTreeMap<CorpusId, Rc<RefCell<T>>>,
    /// A list of available corpus ids
    history: CorpusIdHistory,
}

/// Keep track of the stored `Testcase` and the siblings ids (insertion order)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestcaseStorageItem<T> {
    /// The stored testcase
    pub testcase: Rc<RefCell<T>>,
    /// Previously inserted id
    pub prev: Option<CorpusId>,
    /// Following inserted id
    pub next: Option<CorpusId>,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct HashCorpusMap<T> {
    /// A map of `CorpusId` to `TestcaseStorageItem`
    map: hashbrown::HashMap<CorpusId, TestcaseStorageItem<T>>,
    /// First inserted id
    first_id: Option<CorpusId>,
    /// Last inserted id
    last_id: Option<CorpusId>,
    /// A list of available corpus ids
    history: CorpusIdHistory,
}

impl CorpusIdHistory {
    ///  Add a key to the history
    pub fn add(&mut self, id: CorpusId) {
        if let Err(idx) = self.keys.binary_search(&id) {
            self.keys.insert(idx, id);
        }
    }

    /// Remove a key from the history
    fn remove(&mut self, id: CorpusId) {
        if let Ok(idx) = self.keys.binary_search(&id) {
            self.keys.remove(idx);
        }
    }

    // Get the nth item from the map
    fn nth(&self, idx: usize) -> CorpusId {
        self.keys[idx]
    }
}

impl<T> InMemoryCorpusMap<T> for HashCorpusMap<T> {
    fn count(&self) -> usize {
        self.map.len()
    }

    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn add(&mut self, id: CorpusId, testcase: T) {
        let prev = if let Some(last_id) = self.last_id {
            self.map.get_mut(&last_id).unwrap().next = Some(id);
            Some(last_id)
        } else {
            None
        };

        if self.first_id.is_none() {
            self.first_id = Some(id);
        }

        self.last_id = Some(id);

        self.history.add(id);

        self.map.insert(
            id,
            TestcaseStorageItem {
                testcase: Rc::new(RefCell::new(testcase)),
                prev,
                next: None,
            },
        );
    }

    fn replace(&mut self, id: CorpusId, new_testcase: T) -> Option<T> {
        match self.map.get_mut(&id) {
            Some(entry) => Some(entry.testcase.replace(new_testcase)),
            _ => None,
        }
    }

    fn remove(&mut self, id: CorpusId) -> Option<Rc<RefCell<T>>> {
        if let Some(item) = self.map.remove(&id) {
            if let Some(prev) = item.prev {
                self.history.remove(id);
                self.map.get_mut(&prev).unwrap().next = item.next;
            } else {
                // first elem
                self.first_id = item.next;
            }

            if let Some(next) = item.next {
                self.map.get_mut(&next).unwrap().prev = item.prev;
            } else {
                // last elem
                self.last_id = item.prev;
            }

            Some(item.testcase)
        } else {
            None
        }
    }

    fn get(&self, id: CorpusId) -> Option<Rc<RefCell<T>>> {
        self.map.get(&id).map(|inner| inner.testcase.clone())
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        match self.map.get(&id) {
            Some(item) => item.prev,
            _ => None,
        }
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        match self.map.get(&id) {
            Some(item) => item.next,
            _ => None,
        }
    }

    fn first(&self) -> Option<CorpusId> {
        self.first_id
    }

    fn last(&self) -> Option<CorpusId> {
        self.last_id
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.history.nth(nth)
    }
}

impl<T> InMemoryCorpusMap<T> for BtreeCorpusMap<T> {
    fn count(&self) -> usize {
        self.map.len()
    }

    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn add(&mut self, id: CorpusId, testcase: T) {
        // corpus.insert_key(id);
        self.map.insert(id, Rc::new(RefCell::new(testcase)));
        self.history.add(id);
    }

    fn replace(&mut self, id: CorpusId, new_testcase: T) -> Option<T> {
        self.map
            .get_mut(&id)
            .map(|entry| entry.replace(new_testcase))
    }

    fn remove(&mut self, id: CorpusId) -> Option<Rc<RefCell<T>>> {
        self.history.remove(id);
        self.map.remove(&id)
    }

    fn get(&self, id: CorpusId) -> Option<Rc<RefCell<T>>> {
        self.map.get(&id).cloned()
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        // TODO see if using self.keys is faster
        let mut range = self
            .map
            .range((core::ops::Bound::Unbounded, core::ops::Bound::Included(id)));
        if let Some((this_id, _)) = range.next_back() {
            if id != *this_id {
                return None;
            }
        }
        if let Some((prev_id, _)) = range.next_back() {
            Some(*prev_id)
        } else {
            None
        }
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        // TODO see if using self.keys is faster
        let mut range = self
            .map
            .range((core::ops::Bound::Included(id), core::ops::Bound::Unbounded));
        if let Some((this_id, _)) = range.next() {
            if id != *this_id {
                return None;
            }
        }
        if let Some((next_id, _)) = range.next() {
            Some(*next_id)
        } else {
            None
        }
    }

    fn first(&self) -> Option<CorpusId> {
        self.map.iter().next().map(|x| *x.0)
    }

    fn last(&self) -> Option<CorpusId> {
        self.map.iter().next_back().map(|x| *x.0)
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.history.nth(nth)
    }
}
