use core::marker::PhantomData;

use crate::{
    events::{Event, EventManager},
    executors::{Executor, HasObservers},
    feedbacks::FeedbacksTuple,
    inputs::Input,
    mutators::Mutator,
    observers::ObserversTuple,
    stages::Corpus,
    stages::Stage,
    state::{HasCorpus, State},
    utils::Rand,
    AflError,
};

// TODO multi mutators stage

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<C, E, EM, FT, I, M, OT, R>: Stage<C, E, EM, FT, I, OT, R>
where
    M: Mutator<C, I, R, State<C, FT, I, R>>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
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
        state: &mut State<C, FT, I, R>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), AflError> {
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

            let fitness = state.evaluate_input(&input_mut, executor, manager)?;

            self.mutator_mut()
                .post_exec(state, fitness, &input_mut, i as i32)?;

            let observers = executor.observers();

            // put all this shit in some overridable function in engine maybe? or in corpus.
            // consider a corpus that strores new testcases in a temporary queue, for later processing
            // in a late stage, NewTestcase should be triggere donly after the processing in the later stage
            // So by default we shoudl trigger it in corpus.add, so that the user can override it and remove
            // if needed by particular cases
            if fitness > 0 {
                let observers_buf = manager.serialize_observers(observers)?;

                // TODO decouple events manager and engine
                manager.fire(
                    state,
                    Event::NewTestcase {
                        input: input_mut.clone(),
                        observers_buf,
                        corpus_size: state.corpus().count() + 1,
                        client_config: "TODO".into(),
                    },
                )?;
                state.add_if_interesting(input_mut, fitness)?;
            // let _ = corpus.add(testcase);
            } else {
                state.discard_input(&input_mut)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// The default mutational stage
pub struct StdMutationalStage<C, E, EM, FT, I, M, OT, R>
where
    C: Corpus<I, R>,
    E: Executor<I> + HasObservers<OT>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    I: Input,
    M: Mutator<C, I, R, State<C, FT, I, R>>,
    OT: ObserversTuple,
    R: Rand,
{
    mutator: M,
    phantom: PhantomData<(EM, E, OT, FT, C, I, R)>,
}

impl<C, E, EM, FT, I, M, OT, R> MutationalStage<C, E, EM, FT, I, M, OT, R>
    for StdMutationalStage<C, E, EM, FT, I, M, OT, R>
where
    C: Corpus<I, R>,
    E: Executor<I> + HasObservers<OT>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    I: Input,
    M: Mutator<C, I, R, State<C, FT, I, R>>,
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

impl<C, E, EM, FT, I, M, OT, R> Stage<C, E, EM, FT, I, OT, R>
    for StdMutationalStage<C, E, EM, FT, I, M, OT, R>
where
    M: Mutator<C, I, R, State<C, FT, I, R>>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
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
        state: &mut State<C, FT, I, R>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), AflError> {
        self.perform_mutational(rand, executor, state, manager, corpus_idx)
    }
}

impl<C, E, EM, FT, I, M, OT, R> StdMutationalStage<C, E, EM, FT, I, M, OT, R>
where
    M: Mutator<C, I, R, State<C, FT, I, R>>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
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
