use std::marker::PhantomData;

use libafl::{
    corpus::{Corpus, CorpusId, HasTestcase, SchedulerTestcaseMetadata, Testcase},
    inputs::{Input, UsesInput},
    observers::{CanTrack, ObserversTuple},
    schedulers::{
        HasQueueCycles, MinimizerScheduler, RemovableScheduler, Scheduler, TestcaseScore,
    },
    state::{HasCorpus, HasRand, State},
    Error, HasMetadata,
};
use libafl_bolts::{serdeany::SerdeAny, AsIter, HasRefCnt};

pub enum SupportedSchedulers<CS, F, I, M, O, S, Q> {
    Queue(Q, PhantomData<(CS, F, I, M, O, S, Q)>),
    Weighted(
        MinimizerScheduler<CS, F, I, M, O, S>,
        PhantomData<(CS, F, I, M, O, S, Q)>,
    ),
}

impl<CS, F, I, M, O, S, Q> RemovableScheduler<I, S> for SupportedSchedulers<CS, F, I, M, O, S, Q>
where
    CS: Scheduler<I, S> + RemovableScheduler<I, S>,
    F: TestcaseScore<I, S>,
    I: Input,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,
    O: CanTrack,
    Q: Scheduler<I, S> + RemovableScheduler<I, S>,
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus<Input = I> + HasRand + State,
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

impl<CS, F, I, M, O, S, Q> Scheduler<I, S> for SupportedSchedulers<CS, F, I, M, O, S, Q>
where
    CS: Scheduler<I, S>,
    F: TestcaseScore<I, S>,
    I: Input,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,
    O: CanTrack,
    Q: Scheduler<I, S>,
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus<Input = I> + HasRand + State,
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
        OTB: ObserversTuple<S>,
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

impl<CS, F, I, M, O, S, Q> HasQueueCycles for SupportedSchedulers<CS, F, I, M, O, S, Q>
where
    CS: Scheduler<I, S> + HasQueueCycles,
    F: TestcaseScore<I, S>,
    I: Input,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,

    O: CanTrack,
    Q: Scheduler<I, S> + HasQueueCycles,
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus<Input = I> + HasRand + State,
{
    fn queue_cycles(&self) -> u64 {
        match self {
            Self::Queue(queue, _) => queue.queue_cycles(),
            Self::Weighted(weighted, _) => weighted.base().queue_cycles(),
        }
    }
}
