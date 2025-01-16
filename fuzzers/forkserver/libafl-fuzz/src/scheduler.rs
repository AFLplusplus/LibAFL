use std::marker::PhantomData;

use libafl::{
    corpus::{Corpus, CorpusId, HasTestcase, SchedulerTestcaseMetadata, Testcase},
    schedulers::{HasQueueCycles, RemovableScheduler, Scheduler},
    state::HasCorpus,
    Error, HasMetadata,
};
use libafl_bolts::tuples::MatchName;

pub enum SupportedSchedulers<Q, W> {
    Queue(Q, PhantomData<W>),
    Weighted(W, PhantomData<Q>),
}

impl<I, Q, S, W> RemovableScheduler<I, S> for SupportedSchedulers<Q, W>
where
    Q: Scheduler<I, S> + RemovableScheduler<I, S>,
    W: Scheduler<I, S> + RemovableScheduler<I, S>,
    S: HasTestcase<I>,
{
    fn on_remove(
        &mut self,
        state: &mut S,
        id: CorpusId,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.on_remove(state, id, testcase),
            Self::Weighted(weighted, _) => weighted.on_remove(state, id, testcase),
        }
    }

    fn on_replace(&mut self, state: &mut S, id: CorpusId, prev: &Testcase<I>) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.on_replace(state, id, prev),
            Self::Weighted(weighted, _) => weighted.on_replace(state, id, prev),
        }
    }
}

impl<I, Q, S, W> Scheduler<I, S> for SupportedSchedulers<Q, W>
where
    Q: Scheduler<I, S>,
    W: Scheduler<I, S>,
    S: HasCorpus<I> + HasTestcase<I>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        match self {
            // We need to manually set the depth
            // since we want to avoid implementing `AflScheduler` for `QueueScheduler`
            Self::Queue(queue, _) => {
                queue.on_add(state, id)?;
                let current_id = *state.corpus().current();
                let mut depth = match current_id {
                    Some(parent_idx) => state
                        .testcase(parent_idx)?
                        .metadata::<SchedulerTestcaseMetadata>()?
                        .depth(),
                    None => 0,
                };
                depth += 1;
                let mut testcase = state.corpus().get(id)?.borrow_mut();
                testcase.add_metadata(SchedulerTestcaseMetadata::new(depth));
                Ok(())
            }
            Self::Weighted(weighted, _) => weighted.on_add(state, id),
        }
    }

    /// Gets the next entry in the queue
    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        match self {
            Self::Queue(queue, _) => queue.next(state),
            Self::Weighted(weighted, _) => weighted.next(state),
        }
    }
    fn on_evaluation<OTB>(&mut self, state: &mut S, input: &I, observers: &OTB) -> Result<(), Error>
    where
        OTB: MatchName,
    {
        match self {
            Self::Queue(queue, _) => queue.on_evaluation(state, input, observers),
            Self::Weighted(weighted, _) => weighted.on_evaluation(state, input, observers),
        }
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.set_current_scheduled(state, next_id),
            Self::Weighted(weighted, _) => weighted.set_current_scheduled(state, next_id),
        }
    }
}

impl<Q, W> HasQueueCycles for SupportedSchedulers<Q, W>
where
    Q: HasQueueCycles,
    W: HasQueueCycles,
{
    fn queue_cycles(&self) -> u64 {
        match self {
            Self::Queue(queue, _) => queue.queue_cycles(),
            Self::Weighted(weighted, _) => weighted.queue_cycles(),
        }
    }
}
