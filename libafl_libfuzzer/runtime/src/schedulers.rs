use std::{collections::BTreeSet, marker::PhantomData};

use hashbrown::HashMap;
use libafl::{
    corpus::{Corpus, CorpusId, Testcase},
    feedbacks::MapNoveltiesMetadata,
    inputs::Input,
    schedulers::{RemovableScheduler, Scheduler},
    state::{HasCorpus, State},
    Error, HasMetadata,
};

#[derive(Clone, Debug)]
pub struct MergeScheduler<I, S> {
    mapping: HashMap<usize, CorpusId>,
    all: BTreeSet<CorpusId>,
    phantom: PhantomData<(I, S)>,
}

impl<I, S> RemovableScheduler<I, S> for MergeScheduler<I, S>
where
    I: Input,
    S: State + HasCorpus,
{
    fn on_remove(
        &mut self,
        _state: &mut S,
        id: CorpusId,
        _testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        self.all.remove(&id);
        Ok(())
    }
}

impl<I, S> Scheduler<I, S> for MergeScheduler<I, S>
where
    S: State + HasCorpus,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        self.all.insert(id);
        let testcase = state.corpus().get(id)?.borrow();
        let meta = testcase.metadata::<MapNoveltiesMetadata>()?;
        for cov_ in &meta.list {
            self.mapping.insert(*cov_, id);
        }
        Ok(())
    }

    fn next(&mut self, _state: &mut S) -> Result<CorpusId, Error> {
        unimplemented!("Not suitable for actual scheduling.");
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        *state.corpus_mut().current_mut() = next_id;
        Ok(())
    }
}

impl<I, S> MergeScheduler<I, S> {
    pub fn new() -> Self {
        Self {
            mapping: HashMap::default(),
            all: BTreeSet::default(),
            phantom: PhantomData,
        }
    }

    pub fn removable(&self) -> BTreeSet<CorpusId> {
        self.all
            .difference(&self.mapping.values().copied().collect())
            .copied()
            .collect()
    }

    pub fn current(&self) -> &BTreeSet<CorpusId> {
        &self.all
    }
}
