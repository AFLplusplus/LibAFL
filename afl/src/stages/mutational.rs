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

use crate::serde_anymap::{Ptr, PtrMut};

// TODO multi mutators stage

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
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
    #[inline]
    fn iterations(&mut self, rand: &mut R) -> usize {
        1 + rand.below(128) as usize
    }

    /// Runs this (mutational) stage for the given testcase
    fn perform_mutational(
        &mut self,
        rand: &mut R,
        state: &mut State<I, R>,
        corpus: &mut C,
        engine: &mut Engine<E, I>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), AflError> {
        let num = self.iterations(rand);
        for i in 0..num {
            let mut input_mut = corpus.get(corpus_idx).borrow_mut().load_input()?.clone();
            self.mutator_mut()
                .mutate(rand, corpus, &mut input_mut, i as i32)?;

            let fitness = state.evaluate_input(&input_mut, engine.executor_mut())?;

            self.mutator_mut()
                .post_exec(fitness, &input_mut, i as i32)?;

            // put all this shit in some overridable function in engine maybe? or in corpus.
            // consider a corpus that strores new testcases in a temporary queue, for later processing
            // in a late stage, NewTestcase should be triggere donly after the processing in the later stage
            // So by default we shoudl trigger it in corpus.add, so that the user can override it and remove
            // if needed by particular cases
            let testcase_maybe = state.testcase_if_interesting(input_mut, fitness)?;
            if let Some(mut testcase) = testcase_maybe {
                // TODO decouple events manager and engine
                manager.fire(
                    Event::NewTestcase {
                        sender_id: 0,
                        input: Ptr::Ref(testcase.load_input()?),
                        observers: PtrMut::Ref(engine.executor_mut().observers_mut()),
                        corpus_count: corpus.count() +1
                    }
                )?;
                let _ = corpus.add(testcase);
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

impl<M, EM, E, C, I, R> Stage<EM, E, C, I, R> for StdMutationalStage<M, EM, E, C, I, R>
where
    M: Mutator<C, I, R>,
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    #[inline]
    fn perform(
        &mut self,
        rand: &mut R,
        state: &mut State<I, R>,
        corpus: &mut C,
        engine: &mut Engine<E, I>,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), AflError> {
        self.perform_mutational(rand, state, corpus, engine, manager, corpus_idx)
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
