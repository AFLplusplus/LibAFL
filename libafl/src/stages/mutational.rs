use core::marker::PhantomData;

use crate::{
    events::EventManager,
    executors::{Executor, HasObservers},
    feedbacks::FeedbacksTuple,
    inputs::Input,
    mutators::Mutator,
    observers::ObserversTuple,
    stages::Corpus,
    stages::Stage,
    state::{HasCorpus, State},
    utils::Rand,
    Error,
};

// TODO multi mutators stage

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<C, E, EM, FT, I, M, OC, OFT, OT, R>:
    Stage<C, E, EM, FT, I, OC, OFT, OT, R>
where
    M: Mutator<C, I, R, State<C, FT, I, OC, OFT, R>>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    /// This call uses internal mutability, so it may change for each call
    #[inline]
    fn iterations(&mut self, rand: &mut R) -> usize {
        1 + rand.below(128) as usize
    }

    /// Runs this (mutational) stage for the given testcase
    fn perform_mutational(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        state: &mut State<C, FT, I, OC, OFT, R>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(rand);
        for i in 0..num {
            let mut input_mut = state
                .corpus()
                .get(corpus_idx)
                .borrow_mut()
                .load_input()?
                .clone();
            self.mutator_mut()
                .mutate(rand, state, &mut input_mut, i as i32)?;

            let fitness = state.process_input(input_mut, executor, manager)?;

            self.mutator_mut().post_exec(state, fitness, i as i32)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// The default mutational stage
pub struct StdMutationalStage<C, E, EM, FT, I, M, OC, OFT, OT, R>
where
    C: Corpus<I, R>,
    E: Executor<I> + HasObservers<OT>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    I: Input,
    M: Mutator<C, I, R, State<C, FT, I, OC, OFT, R>>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
    OT: ObserversTuple,
    R: Rand,
{
    mutator: M,
    phantom: PhantomData<(EM, E, OC, OFT, OT, FT, C, I, R)>,
}

impl<C, E, EM, FT, I, M, OC, OFT, OT, R> MutationalStage<C, E, EM, FT, I, M, OC, OFT, OT, R>
    for StdMutationalStage<C, E, EM, FT, I, M, OC, OFT, OT, R>
where
    C: Corpus<I, R>,
    E: Executor<I> + HasObservers<OT>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    I: Input,
    M: Mutator<C, I, R, State<C, FT, I, OC, OFT, R>>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
    OT: ObserversTuple,
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
}

impl<C, E, EM, FT, I, M, OC, OFT, OT, R> Stage<C, E, EM, FT, I, OC, OFT, OT, R>
    for StdMutationalStage<C, E, EM, FT, I, M, OC, OFT, OT, R>
where
    M: Mutator<C, I, R, State<C, FT, I, OC, OFT, R>>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    #[inline]
    fn perform(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        state: &mut State<C, FT, I, OC, OFT, R>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.perform_mutational(rand, executor, state, manager, corpus_idx)
    }
}

impl<C, E, EM, FT, I, M, OC, OFT, OT, R> StdMutationalStage<C, E, EM, FT, I, M, OC, OFT, OT, R>
where
    M: Mutator<C, I, R, State<C, FT, I, OC, OFT, R>>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
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
