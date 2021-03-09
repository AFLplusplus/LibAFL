use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusScheduler},
    events::EventManager,
    executors::{Executor, HasObservers},
    inputs::Input,
    mutators::Mutator,
    observers::ObserversTuple,
    stages::{Stage, MutationalStage},
    state::{Evaluator, HasCorpus, HasRand},
    utils::Rand,
    Error,
};

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<C, CS, E, EM, I, M, OT, R, S>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasCorpus<C, I> + Evaluator<I> + HasRand<R>,
    C: Corpus<I>,
    EM: EventManager<I, S>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    CS: CorpusScheduler<I, S>,
    R: Rand,
{
    mutator: M,
    phantom: PhantomData<(C, CS, E, EM, I, OT, R, S)>,
}

impl<C, CS, E, EM, I, M, OT, R, S> MutationalStage<C, CS, E, EM, I, M, OT, S>
    for PowerMutationalStage<C, CS, E, EM, I, M, OT, R, S>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasCorpus<C, I> + Evaluator<I> + HasRand<R>,
    C: Corpus<I>,
    EM: EventManager<I, S>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    CS: CorpusScheduler<I, S>,
    R: Rand,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut S) -> usize {
        1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize
    }
}

impl<C, CS, E, EM, I, M, OT, R, S> Stage<CS, E, EM, I, S>
    for PowerMutationalStage<C, CS, E, EM, I, M, OT, R, S>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasCorpus<C, I> + Evaluator<I> + HasRand<R>,
    C: Corpus<I>,
    EM: EventManager<I, S>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    CS: CorpusScheduler<I, S>,
    R: Rand,
{
    #[inline]
    fn perform(
        &self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.perform_mutational(state, executor, manager, scheduler, corpus_idx)
    }
}

impl<C, CS, E, EM, I, M, OT, R, S> PowerMutationalStage<C, CS, E, EM, I, M, OT, R, S>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasCorpus<C, I> + Evaluator<I> + HasRand<R>,
    C: Corpus<I>,
    EM: EventManager<I, S>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    CS: CorpusScheduler<I, S>,
    R: Rand,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self {
            mutator: mutator,
            phantom: PhantomData,
        }
    }
}
