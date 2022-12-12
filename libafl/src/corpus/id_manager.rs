//! The [`CorpusIdManager`] is responsible for keeping track of active [`CorpusId`]s. It lets the corpus map a
//! [`CorpusId`] to its corresponding corpus index to allow for a vector-based corpus storage. It is the only component
//! that should be able to create new [`CorpusId`]s.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::Corpus;
use crate::{
    bolts::rands::Rand,
    state::{HasCorpus, HasRand},
    Error,
};

/// Creates a new [`CorpusId`]. [`CorpusId`]s are globally unique for a corpus and monotonically increasing.
/// They should only ever be created by a [`CorpusIdManager`], everything else must acquire them from one.
/// [`CorpusId`]s allow us to track a testcase uniquely even when corpora can have testcases be removed or replaced.
/// Two different testcases should never have the same [`CorpusId`].
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CorpusId {
    /// Corpus-unique identifier
    id: usize,
}

/// A [`CorpusIdManager`] is responsible for keeping track of active [`CorpusId`]s. It creates new ones, ensures that
/// they are unique, and maps them to their corresponding indices in the corpus. The `active_ids` field
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CorpusIdManager {
    /// Maps a CorpusId to an actual id, or returns false if it was removed
    id_mappings: Vec<Option<usize>>,
    /// A vec of active Ids
    active_ids: Vec<CorpusId>,
}

impl CorpusIdManager {
    /// Creates a new [`CorpusIdManager`].
    #[must_use]
    pub fn new() -> Self {
        CorpusIdManager::default()
    }

    /// Get a slice of the currently active [`CorpusId`]s. The length of this slice should always match the `count()` of
    /// the corpus.
    #[must_use]
    pub fn active_ids(&self) -> &[CorpusId] {
        // should always be sorted, since it only increasing values are ever appended!
        // debug_assert!(self.active_ids.is_sorted());
        &self.active_ids
    }

    /// Allocate the next [`CorpusId`] and return it. This returns a [`CorpusId`] with an identifier larger than all
    /// previously issued [`CorpusId`]s. This new [`CorpusId`] is immediately added to the `active_ids`.
    pub(super) fn provide_next(&mut self) -> Result<CorpusId, Error> {
        let id = CorpusId {
            id: self.id_mappings.len(),
        };
        self.active_ids.push(id);
        self.id_mappings.push(Some(self.active_ids.len()));
        Ok(id)
    }

    /// Invalidate the given [`CorpusId`]. This will cause any future operations and lookups for this [`CorpusId`] to
    /// fail. If the id was valid, returns the index where it was found;
    #[must_use]
    pub(crate) fn remove_id(&mut self, id: CorpusId) -> Option<usize> {
        // debug_assert!(self.active_ids.is_sorted());
        self.id_mappings[id.id].take().map(|idx| {
            self.active_ids.remove(idx);
            idx
        })
    }

    /// Get the corpus index for the given [`CorpusId`]. Should only ever be called by a [`Corpus`].
    #[must_use]
    pub(crate) fn active_index_for(&self, id: CorpusId) -> Option<usize> {
        // debug_assert!(self.active_ids.is_sorted());
        self.id_mappings[id.id]
    }

    /// Get the [`CorpusId`] at the given index. If the index is out of bounds, returns `Err`.
    #[must_use]
    pub fn get(&self, idx: usize) -> Result<CorpusId, Error> {
        self.assert_has_active()?;
        self.active_ids.get(idx).copied().ok_or_else(|| {
            Error::illegal_argument(format!(
                "The given idx {idx} was out of bounds for id_manager (active_ids: {})",
                self.active_ids.len()
            ))
        })
    }

    /// Returns [`Error::Empty`] if no entries are in `active_ids`, else `Ok`
    #[inline]
    fn assert_has_active(&self) -> Result<(), Error> {
        if self.active_ids.is_empty() {
            Err(Error::empty("No active_ids in id_manager"))
        } else {
            Ok(())
        }
    }

    /// Get the id of the first (oldest) active [`CorpusId`].
    #[must_use]
    pub fn first_id(&self) -> Option<CorpusId> {
        self.active_ids.first().copied()
    }

    /// Gets the "next" (least less old) active [`CorpusId`]. This is like incrementing the index.
    #[must_use]
    pub fn find_next(&self, id: CorpusId) -> Option<CorpusId> {
        // it should ALWAYS be sorted since it only ever gets appended to with larger values (next ids)
        // debug_assert!(self.active_ids.is_sorted());

        if let Some(idx) = self.id_mappings[id.id] {
            // get next entry in the active list
            if self.active_ids.len() > idx + 1 {
                return Some(self.active_ids[idx]);
            }
        }
        None
    }

    /// Returns the current idx for the given corpus id
    pub fn lookup(&self, corpus_id: CorpusId) -> Option<usize> {
        self.id_mappings[corpus_id.id]
    }
}

/// Return a random entry from the corpus of a given state. This function is mainly for encapsulation to make the borrow
/// checker happy and keep the random index creation confined to one spot.
pub fn random_corpus_entry<S>(state: &mut S) -> Result<CorpusId, Error>
where
    S: HasCorpus + HasRand,
{
    let num = state.corpus().count();
    if num == 0 {
        return Err(Error::empty("No active_ids in id_manager"));
    }
    let idx = state.rand_mut().below(num.try_into().unwrap()) as usize;
    let id = state
        .corpus()
        .id_manager()
        .get(idx)
        .expect("this should never fail, our random value should always be inbounds");
    Ok(id)
}
