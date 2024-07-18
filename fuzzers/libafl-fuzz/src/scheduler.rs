use std::marker::PhantomData;

use libafl::{
    corpus::{CorpusId, HasTestcase, Testcase},
    inputs::UsesInput,
    observers::{CanTrack, ObserversTuple},
    schedulers::{HasQueueCycles, MinimizerScheduler, RemovableScheduler, Scheduler, TestcaseScore},
    state::{HasCorpus, HasRand, State, UsesState},
    Error, HasMetadata,
};
use libafl_bolts::{serdeany::SerdeAny, AsIter, HasRefCnt};

pub enum SupportedSchedulers<S, Q, CS, F, M, O> {
    Queue(Q, PhantomData<(S, Q, CS, F, M, O)>),
    Weighted(MinimizerScheduler<CS, F, M, O>, PhantomData<(S, Q, CS, F, M, O)>),
}

impl<S, Q, CS, F, M, O> UsesState for SupportedSchedulers<S, Q, CS, F, M, O>
where
    S: State + HasRand + HasCorpus + HasMetadata + HasTestcase,
{
    type State = S;
}

impl<S, Q, CS, F, M, O> RemovableScheduler for SupportedSchedulers<S, Q, CS, F, M, O>
where
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus + HasRand + State,
    Q: Scheduler<State = S> + RemovableScheduler,
    CS: RemovableScheduler<State = S>,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,
    O: CanTrack,
    F: TestcaseScore<S>,
{
    fn on_remove(
        &mut self,
        state: &mut Self::State,
        id: CorpusId,
        testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.on_remove(state, id, testcase),
            Self::Weighted(weighted, _) => weighted.on_remove(state, id, testcase),
        }
    }

    fn on_replace(
        &mut self,
        state: &mut Self::State,
        id: CorpusId,
        prev: &Testcase<<Self::State as UsesInput>::Input>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.on_replace(state, id, prev),
            Self::Weighted(weighted, _) => weighted.on_replace(state, id, prev),
        }
    }
}

impl<S, Q, CS, F, M, O> Scheduler for SupportedSchedulers<S, Q, CS, F, M, O>
where
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus + HasRand + State,
    Q: Scheduler<State = S>,
    CS: Scheduler<State = S>,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,
    O: CanTrack,
    F: TestcaseScore<S>
{
    fn on_add(&mut self, state: &mut Self::State, id: CorpusId) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.on_add(state, id),
            Self::Weighted(weighted, _) => weighted.on_add(state, id),
        }
    }

    /// Gets the next entry in the queue
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        match self {
            Self::Queue(queue, _) => queue.next(state),
            Self::Weighted(weighted, _) => weighted.next(state),
        }
    }
    fn on_evaluation<OTB>(
        &mut self,
        state: &mut Self::State,
        input: &<Self::State as UsesInput>::Input,
        observers: &OTB,
    ) -> Result<(), Error>
    where
        OTB: ObserversTuple<Self::State>,
    {
        match self {
            Self::Queue(queue, _) => queue.on_evaluation(state, input, observers),
            Self::Weighted(weighted, _) => weighted.on_evaluation(state, input, observers),
        }
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut Self::State,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        match self {
            Self::Queue(queue, _) => queue.set_current_scheduled(state, next_id),
            Self::Weighted(weighted, _) => weighted.set_current_scheduled(state, next_id),
        }
    }
}

impl<S, Q, CS, F, M, O> HasQueueCycles for SupportedSchedulers<S, Q, CS, F, M, O>
where
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus + HasRand + State,
    Q: Scheduler<State = S> + HasQueueCycles,
    CS: Scheduler<State = S> + HasQueueCycles,
    O: CanTrack,
    M: for<'a> AsIter<'a, Item = usize> + SerdeAny + HasRefCnt,
    F: TestcaseScore<S>
{
    fn queue_cycles(&self) -> u64 {
        match self {
            Self::Queue(queue, _) => queue.queue_cycles(),
            Self::Weighted(weighted, _) => weighted.base().queue_cycles(),
        }
    }
}
