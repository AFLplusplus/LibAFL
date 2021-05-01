use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusScheduler},
    events::EventManager,
    executors::{Executor, HasObservers},
    inputs::Input,
    mutators::Mutator,
    observers::ObserversTuple,
    stages::Stage,
    state::{Evaluator, HasCorpus, HasRand},
    utils::Rand,
    Error,
};

// TODO multi mutators stage

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<C, CS, E, EM, I, M, OT, S>: Stage<CS, E, EM, I, S>
where
    M: Mutator<I, S>,
    I: Input,
    S: HasCorpus<C, I> + Evaluator<I>,
    C: Corpus<I>,
    EM: EventManager<I, S>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    CS: CorpusScheduler<I, S>,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut S) -> usize;

    /// Runs this (mutational) stage for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(state);
        for i in 0..num {
            let mut input_mut = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            self.mutator_mut().mutate(state, &mut input_mut, i as i32)?;
            let (_, corpus_idx) = state.evaluate_input(input_mut, executor, manager, scheduler)?;

            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
        }
        Ok(())
    }
}

pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct StdMutationalStage<C, CS, E, EM, I, M, OT, R, S>
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
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, CS, E, EM, I, OT, R, S)>,
}

impl<C, CS, E, EM, I, M, OT, R, S> MutationalStage<C, CS, E, EM, I, M, OT, S>
    for StdMutationalStage<C, CS, E, EM, I, M, OT, R, S>
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
    for StdMutationalStage<C, CS, E, EM, I, M, OT, R, S>
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
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.perform_mutational(state, executor, manager, scheduler, corpus_idx)
    }
}

impl<C, CS, E, EM, I, M, OT, R, S> StdMutationalStage<C, CS, E, EM, I, M, OT, R, S>
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
            mutator,
            phantom: PhantomData,
        }
    }
}
