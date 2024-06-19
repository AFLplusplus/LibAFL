use std::{
    collections::{BTreeSet, HashMap},
    marker::PhantomData,
};

use libafl::{
    corpus::{Corpus, CorpusId, Testcase},
    feedbacks::MapNoveltiesMetadata,
    inputs::UsesInput,
    schedulers::{RemovableScheduler, Scheduler},
    state::{HasCorpus, State, UsesState},
    Error, HasMetadata,
};

#[derive(Clone, Debug)]
pub struct MergeScheduler<S> {
    mapping: HashMap<usize, CorpusId>,
    all: BTreeSet<CorpusId>,
    phantom: PhantomData<S>,
}

impl<S> UsesState for MergeScheduler<S>
where
    S: State,
{
    type State = S;
}

impl<S> RemovableScheduler for MergeScheduler<S>
where
    S: State + HasCorpus,
{
    fn on_remove(
        &mut self,
        _state: &mut Self::State,
        id: CorpusId,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        self.all.remove(&id);
        Ok(())
    }
}

impl<S> Scheduler for MergeScheduler<S>
where
    S: State + HasCorpus,
{
    fn on_add(&mut self, state: &mut Self::State, id: CorpusId) -> Result<(), Error> {
        self.all.insert(id);
        let testcase = state.corpus().get(id)?.borrow();
        let meta = testcase.metadata::<MapNoveltiesMetadata>()?;
        for cov_ in &meta.list {
            self.mapping.insert(*cov_, id);
        }
        Ok(())
    }

    fn next(&mut self, _state: &mut Self::State) -> Result<CorpusId, Error> {
        unimplemented!("Not suitable for actual scheduling.");
    }
}

impl<S> MergeScheduler<S> {
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
