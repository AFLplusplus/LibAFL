use std::marker::PhantomData;

use libafl::{
    corpus::{CorpusId, HasTestcase, Testcase},
    inputs::UsesInput,
    observers::ObserversTuple,
    schedulers::{RemovableScheduler, Scheduler},
    state::{HasCorpus, HasRand, State, UsesState},
    Error, HasMetadata,
};

pub enum SupportedSchedulers<S, Q, W> {
    Queue(Q, PhantomData<S>),
    Weighted(W, PhantomData<S>),
}

impl<S, Q, W> UsesState for SupportedSchedulers<S, Q, W>
where
    S: State + HasRand + HasCorpus + HasMetadata + HasTestcase,
{
    type State = S;
}

impl<S, Q, W> RemovableScheduler for SupportedSchedulers<S, Q, W>
where
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus + HasRand + State,
    Q: Scheduler<State = S> + RemovableScheduler,
    W: Scheduler<State = S> + RemovableScheduler,
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

impl<S, Q, W> Scheduler for SupportedSchedulers<S, Q, W>
where
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus + HasRand + State,
    Q: Scheduler<State = S>,
    W: Scheduler<State = S>,
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
