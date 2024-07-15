use std::marker::PhantomData;

use libafl::{
    corpus::{CorpusId, HasTestcase, Testcase},
    inputs::UsesInput,
    observers::{MapObserver, ObserversTuple},
    schedulers::{AflScheduler, RemovableScheduler, Scheduler},
    state::{HasCorpus, HasRand, State, UsesState},
    Error, HasMetadata,
};
use libafl_bolts::{
    tuples::{Handle, Handled},
    Named,
};

pub enum SupportedSchedulers<S, Q, W, C, O> {
    Queue(Q, PhantomData<(S, Q, W, C, O)>),
    Weighted(W, PhantomData<(S, Q, W, C, O)>),
}

impl<S, Q, W, C, O> UsesState for SupportedSchedulers<S, Q, W, C, O>
where
    S: State + HasRand + HasCorpus + HasMetadata + HasTestcase,
{
    type State = S;
}

impl<S, Q, W, C, O> RemovableScheduler for SupportedSchedulers<S, Q, W, C, O>
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

impl<S, Q, W, C, O> Scheduler for SupportedSchedulers<S, Q, W, C, O>
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

impl<S, Q, W, C, O> AflScheduler<C, O, S> for SupportedSchedulers<S, Q, W, C, O>
where
    O: MapObserver,
    C: AsRef<O> + Named,
    S: UsesInput + HasTestcase + HasMetadata + HasCorpus + HasRand + State,
    Q: Scheduler<State = S> + RemovableScheduler + AflScheduler<C, O, S>,
    W: Scheduler<State = S> + RemovableScheduler + AflScheduler<C, O, S>,
{
    fn last_hash(&self) -> usize {
        match self {
            Self::Queue(queue, _) => queue.last_hash(),
            Self::Weighted(weighted, _) => weighted.last_hash(),
        }
    }

    fn set_last_hash(&mut self, hash: usize) {
        match self {
            Self::Queue(queue, _) => queue.set_last_hash(hash),
            Self::Weighted(weighted, _) => weighted.set_last_hash(hash),
        }
    }

    fn map_observer_handle(&self) -> &Handle<C> {
        match self {
            Self::Queue(queue, _) => queue.map_observer_handle(),
            Self::Weighted(weighted, _) => weighted.map_observer_handle(),
        }
    }

    fn queue_cycles(&self) -> u64 {
        match self {
            Self::Queue(queue, _) => queue.queue_cycles(),
            Self::Weighted(weighted, _) => weighted.queue_cycles(),
        }
    }
}
