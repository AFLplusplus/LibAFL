use core::marker::PhantomData;

use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, CorpusScheduler, PowerScheduleData},
    events::EventManager,
    executors::{Executor, HasObservers},
    fuzzer::Evaluator,
    inputs::Input,
    mutators::Mutator,
    observers::ObserversTuple,
    stages::{MutationalStage, Stage},
    state::{HasClientPerfStats, HasCorpus, HasMetadata, HasRand},
    Error,
};

pub enum PowerSchedule {
    EXPLORE,
    FAST,
    COE,
    LIN,
    QUAD,
    EXPLOIT,
}

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<C, E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfStats + HasCorpus<C, I>,
    C: Corpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    phantom: PhantomData<(C, E, EM, I, S, Z)>,
}

impl<C, E, EM, I, M, S, Z> MutationalStage<C, E, EM, I, M, S, Z>
    for PowerMutationalStage<C, E, EM, I, M, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfStats + HasCorpus<C, I>,
    Z: Evaluator<E, EM, I, S>,
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
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error> {
        let mut testcase = state.corpus().get(corpus_idx).unwrap().borrow_mut();
        let psdata = testcase
            .metadata_mut()
            .get_mut::<PowerScheduleData>()
            .unwrap();
        // 1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize
        Ok(self.calculate_score(psdata))
    }
}

impl<C, E, EM, I, M, S, Z> Stage<E, EM, S, Z> for PowerMutationalStage<C, E, EM, I, M, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfStats + HasCorpus<C, I>,
    Z: Evaluator<E, EM, I, S>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager, corpus_idx);
        ret
    }
}

impl<C, E, EM, I, M, S, Z> PowerMutationalStage<C, E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasClientPerfStats + HasCorpus<C, I>,
    C: Corpus<I>,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self {
            mutator: mutator,
            phantom: PhantomData,
        }
    }

    #[inline]
    fn calculate_score(&self, psdata: &PowerScheduleData) -> usize {
        let mut perf_score = 100;

        perf_score
    }
}
