//! Multiple map implementations for the in-memory store.

use alloc::{collections::BTreeMap, vec::Vec};

use num_traits::Zero;
use serde::{Deserialize, Serialize};

use crate::corpus::{CorpusId, IsTestcaseMetadataCell, TestcaseMetadata};

/// A trait implemented by in-memory corpus maps
pub trait InMemoryCorpusMap<T> {
    /// Returns the number of testcases
    fn count(&self) -> usize;

    /// Returns true, if no elements are in this corpus yet
    fn is_empty(&self) -> bool {
        self.count().is_zero()
    }

    /// Store the testcase associated to `corpus_id`.
    fn add(&mut self, id: CorpusId, testcase: T);

    /// Get by id; considers only enabled testcases
    fn get(&self, id: CorpusId) -> Option<&T>;

    /// Get by id; considers only enabled testcases
    fn get_mut(&mut self, id: CorpusId) -> Option<&mut T>;

    /// Remove a testcase from the map, returning the removed testcase if present.
    fn remove(&mut self, id: CorpusId) -> Option<T>;

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

/// A corpus map for testcases.
pub trait InMemoryTestcaseMap<T>: InMemoryCorpusMap<T> {
    /// Replace the metadata of a given testcase
    fn replace_metadata(
        &mut self,
        id: CorpusId,
        testcase_metadata: TestcaseMetadata,
    ) -> Option<TestcaseMetadata>;
}

/// A history for [`CorpusId`]
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct CorpusIdHistory {
    keys: Vec<CorpusId>,
}

/// A [`BTreeMap`] based [`InMemoryCorpusMap`]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BtreeCorpusMap<T> {
    /// A map of `CorpusId` to `Testcase`.
    map: BTreeMap<CorpusId, T>,
    /// A list of available corpus ids
    history: CorpusIdHistory,
}

/// Keep track of the stored `Testcase` and the siblings ids (insertion order)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestcaseStorageItem<T> {
    /// The stored testcase
    pub testcase: T,
    /// Previously inserted id
    pub prev: Option<CorpusId>,
    /// Following inserted id
    pub next: Option<CorpusId>,
}

/// A [`hashbrown::HashMap`] based [`InMemoryCorpusMap`]
#[derive(Serialize, Deserialize, Clone, Debug)]
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

impl<T> Default for BtreeCorpusMap<T> {
    fn default() -> Self {
        Self {
            map: BTreeMap::default(),
            history: CorpusIdHistory::default(),
        }
    }
}

impl<T> Default for HashCorpusMap<T> {
    fn default() -> Self {
        Self {
            map: hashbrown::HashMap::default(),
            first_id: None,
            last_id: None,
            history: CorpusIdHistory::default(),
        }
    }
}

impl CorpusIdHistory {
    ///  Add a key to the history
    pub fn add(&mut self, id: CorpusId) {
        if let Err(idx) = self.keys.binary_search(&id) {
            self.keys.insert(idx, id);
        }
    }

    /// Remove a key from the history
    pub fn remove(&mut self, id: CorpusId) {
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
                testcase,
                prev,
                next: None,
            },
        );
    }

    fn get(&self, id: CorpusId) -> Option<&T> {
        self.map.get(&id).map(|inner| &inner.testcase)
    }

    fn get_mut(&mut self, id: CorpusId) -> Option<&mut T> {
        self.map.get_mut(&id).map(|storage| &mut storage.testcase)
    }

    fn remove(&mut self, id: CorpusId) -> Option<T> {
        let entry = self.map.remove(&id)?;
        self.history.remove(id);

        if let Some(prev) = &entry.prev {
            self.map.get_mut(prev).unwrap().next = entry.next;
        }

        if let Some(next) = &entry.next {
            self.map.get_mut(next).unwrap().prev = entry.prev;
        }

        Some(entry.testcase)
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

impl<T> InMemoryTestcaseMap<T> for HashCorpusMap<T>
where
    T: IsTestcaseMetadataCell,
{
    fn replace_metadata(
        &mut self,
        id: CorpusId,
        testcase_metadata: TestcaseMetadata,
    ) -> Option<TestcaseMetadata> {
        let old_tc = self.map.get_mut(&id)?;
        Some(old_tc.testcase.replace_testcase_metadata(testcase_metadata))
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
        self.map.insert(id, testcase);
        self.history.add(id);
    }

    fn get(&self, id: CorpusId) -> Option<&T> {
        self.map.get(&id)
    }

    fn get_mut(&mut self, id: CorpusId) -> Option<&mut T> {
        self.map.get_mut(&id)
    }

    fn remove(&mut self, id: CorpusId) -> Option<T> {
        let ret = self.map.remove(&id)?;
        self.history.remove(id);
        Some(ret)
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

impl<T> InMemoryTestcaseMap<T> for BtreeCorpusMap<T>
where
    T: IsTestcaseMetadataCell,
{
    fn replace_metadata(
        &mut self,
        id: CorpusId,
        testcase_metadata: TestcaseMetadata,
    ) -> Option<TestcaseMetadata> {
        let tc = self.get_mut(id)?;
        Some(tc.replace_testcase_metadata(testcase_metadata))
    }
}
