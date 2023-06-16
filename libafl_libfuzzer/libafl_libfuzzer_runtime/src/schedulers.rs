use libafl::corpus::{Corpus, CorpusId, Testcase};
use libafl::feedbacks::MapNoveltiesMetadata;
use libafl::inputs::UsesInput;
use libafl::schedulers::{RemovableScheduler, Scheduler};
use libafl::state::{HasCorpus, HasMetadata, UsesState};
use libafl::Error;
use std::collections::{BTreeSet, HashMap};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct MergeScheduler<S> {
    mapping: HashMap<usize, CorpusId>,
    all: BTreeSet<CorpusId>,
    phantom: PhantomData<S>,
}

impl<S> UsesState for MergeScheduler<S>
where
    S: UsesInput,
{
    type State = S;
}

impl<S> RemovableScheduler for MergeScheduler<S>
where
    S: UsesInput + HasCorpus,
{
    fn on_remove(
        &mut self,
        _state: &mut Self::State,
        idx: CorpusId,
        _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        self.all.remove(&idx);
        Ok(())
    }
}

impl<S> Scheduler for MergeScheduler<S>
where
    S: UsesInput + HasCorpus,
{
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        self.all.insert(idx);
        let testcase = state.corpus().get(idx)?.borrow();
        let meta = testcase.metadata::<MapNoveltiesMetadata>()?;
        for cov_idx in &meta.list {
            self.mapping.insert(*cov_idx, idx);
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
            mapping: Default::default(),
            all: Default::default(),
            phantom: PhantomData,
        }
    }

    pub fn removable(&self) -> BTreeSet<CorpusId> {
        self.all
            .difference(&self.mapping.values().copied().collect())
            .copied()
            .collect()
    }
}
