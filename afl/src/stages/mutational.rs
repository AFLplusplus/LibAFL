use core::marker::PhantomData;

use crate::events::EventManager;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::mutators::Mutator;
use crate::stages::Corpus;
use crate::stages::{Engine, Stage};
use crate::utils::Rand;
use crate::AflError;
use crate::{engines::State, events::Event};

// TODO multi mutators stage

pub trait MutationalStage<M, EM, E, C, I, R>: Stage<EM, E, C, I, R>
where
    M: Mutator<C, I, R>,
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
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
    fn iterations(&mut self, rand: &mut R) -> usize {
        1 + rand.below(128) as usize
    }

    /// Runs this (mutational) stage for the given testcase
    fn perform_mutational(
        &mut self,
        rand: &mut R,
        state: &mut State<I, R>,
        corpus: &mut C,
        engine: &mut Engine<EM, E, C, I, R>,
        input: &I,
    ) -> Result<(), AflError> {
        let num = self.iterations(rand);
        for i in 0..num {
            let mut input_mut = input.clone();
            self.mutator_mut()
                .mutate(rand, corpus, &mut input_mut, i as i32)?;

            let fitness = state.evaluate_input(&input_mut, engine)?;

            self.mutator_mut()
                .post_exec(fitness, &input_mut, i as i32)?;

            let testcase_maybe = state.testcase_if_interesting(input_mut, fitness)?;
            if let Some(testcase) = testcase_maybe {
                //corpus.entries()[idx]
                engine.events_manager_mut().fire(
                    Event::NewTestcase {
                        sender_id: 0,
                        testcase: testcase,
                        phantom: PhantomData,
                    },
                    state,
                    corpus,
                )?;
            }
        }
        Ok(())
    }
}

/// The default mutational stage
pub struct StdMutationalStage<M, EM, E, C, I, R>
where
    M: Mutator<C, I, R>,
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    mutator: M,
    phantom: PhantomData<(EM, E, C, I, R)>,
}

impl<M, EM, E, C, I, R> MutationalStage<M, EM, E, C, I, R> for StdMutationalStage<M, EM, E, C, I, R>
where
    M: Mutator<C, I, R>,
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// The mutator, added to this stage
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }
}

impl<M, EM, E, C, I, R> Stage<EM, E, C, I, R> for StdMutationalStage<M, EM, E, C, I, R>
where
    M: Mutator<C, I, R>,
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn perform(
        &mut self,
        rand: &mut R,
        state: &mut State<I, R>,
        corpus: &mut C,
        engine: &mut Engine<EM, E, C, I, R>,
        input: &I,
    ) -> Result<(), AflError> {
        self.perform_mutational(rand, state, corpus, engine, input)
    }
}

impl<M, EM, E, C, I, R> StdMutationalStage<M, EM, E, C, I, R>
where
    M: Mutator<C, I, R>,
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
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
