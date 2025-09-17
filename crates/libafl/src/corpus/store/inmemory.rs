//! An in-memory store

use alloc::rc::Rc;
use core::marker::PhantomData;

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use super::{InMemoryCorpusMap, Store};
use crate::{
    corpus::{
        CorpusId, Testcase,
        testcase::{HasInstantiableTestcaseMetadata, TestcaseMetadata},
    },
    inputs::Input,
};

/// The map type in which testcases are stored (disable the feature `corpus_btreemap` to use a `HashMap` instead of `BTreeMap`)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InMemoryStore<I, M, TMC> {
    enabled_map: M,
    disabled_map: M,
    phantom: PhantomData<(I, TMC)>,
}

impl<I, M, TMC> Default for InMemoryStore<I, M, TMC>
where
    M: Default,
{
    fn default() -> Self {
        Self {
            enabled_map: M::default(),
            disabled_map: M::default(),
            phantom: PhantomData,
        }
    }
}

impl<I, M, TMC> Store<I> for InMemoryStore<I, M, TMC>
where
    M: InMemoryCorpusMap<Testcase<I, TMC>>,
    TMC: HasInstantiableTestcaseMetadata + Clone,
    I: Input,
{
    type TestcaseMetadataCell = TMC;

    fn count(&self) -> usize {
        self.enabled_map.count()
    }

    fn count_disabled(&self) -> usize {
        self.disabled_map.count()
    }

    fn is_empty(&self) -> bool {
        self.enabled_map.is_empty()
    }

    fn add(&mut self, id: CorpusId, input: Rc<I>, md: TestcaseMetadata) -> Result<(), Error> {
        Ok(self
            .enabled_map
            .add(id, Testcase::new(input, TMC::instantiate(md))))
    }

    fn add_disabled(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        md: TestcaseMetadata,
    ) -> Result<(), Error> {
        Ok(self
            .disabled_map
            .add(id, Testcase::new(input, TMC::instantiate(md))))
    }

    fn get_from<const ENABLED: bool>(
        &self,
        id: CorpusId,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        if ENABLED {
            self.enabled_map
                .get(id)
                .cloned()
                .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))
        } else {
            let mut testcase = self.enabled_map.get(id);

            if testcase.is_none() {
                testcase = self.disabled_map.get(id);
            }

            testcase
                .cloned()
                .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))
        }
    }

    fn replace(
        &mut self,
        id: CorpusId,
        input: Rc<I>,
        metadata: TestcaseMetadata,
    ) -> Result<Testcase<I, Self::TestcaseMetadataCell>, Error> {
        Ok(self
            .enabled_map
            .replace(id, Testcase::new(input, TMC::instantiate(metadata)))
            .ok_or_else(|| Error::key_not_found(format!("Index {id} not found")))?)
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
