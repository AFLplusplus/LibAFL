use core::fmt::{Formatter, Display};
use serde::{Serialize, Deserialize};
use alloc::vec::Vec;

use super::Corpus;

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CorpusID {
    identifier: usize,
}
impl CorpusID {
    fn new(id: usize) -> CorpusID {
        CorpusID { identifier: id }
    }
}
impl Display for CorpusID {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "CorpusID[#{}]", self.identifier)
    }
}
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CorpusIDManager {
    next: usize,
    active_ids_: Vec<CorpusID>,
}

impl CorpusIDManager {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn active_ids(&self) -> &[CorpusID] {
        // should always be sorted, since it only increasing values are ever appended!
        debug_assert!(self.active_ids_.is_sorted());
        &self.active_ids_
    }

    fn provide_next(&mut self) -> CorpusID {
        let val = self.next;
        self.next = val.checked_add(1).unwrap();
        let id = CorpusID { identifier: val };
        self.active_ids_.push(id);
        id
    }

    fn invalidate(&mut self, id: CorpusID) {
        self.active_ids_.retain(|x| x != &id);
    }

    fn invalidate_multiple(&mut self, ids: &[CorpusID]) {
        self.active_ids_.retain(|x| !ids.contains(x));
    }

    fn active_index_for(&self, id: CorpusID) -> Option<usize> {
        self.active_ids_.iter().position(|x| *x == id)
    }

    pub fn get(&self, idx: usize) -> Option<CorpusID> {
        self.active_ids_.get(idx).map(|x| *x)
    }

    pub fn first_id(&self) -> Option<CorpusID> {
        self.active_ids_.first().map(|x| *x)
    }
    pub fn find_next(&self, id: CorpusID) -> Option<CorpusID> {
        // it should ALWAYS be sorted since it only ever gets appended to with larger values (next ids)
        debug_assert!(self.active_ids_.is_sorted());

        self.active_ids_.iter()
            .find(|x| x.identifier > id.identifier)
            .map(|x|*x)
    }
}