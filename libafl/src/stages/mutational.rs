use core::marker::PhantomData;

use crate::{
    events::EventManager,
    executors::{Executor},
    inputs::Input,
    mutators::Mutator,
    stages::Corpus,
    stages::Stage,
    state::{HasRand},
    utils::Rand,
    state::HasCorpus,
    Error,
};

// TODO multi mutators stage

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<I, M>: Stage<I>
where
    M: Mutator<I>,
    I: Input,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations<S>(&mut self, state: &mut S) -> usize;

    /// Runs this (mutational) stage for the given testcase
    fn perform_mutational<E, EM, S, C>(
        &self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>
    where
        EM: EventManager<I>,
        E: Executor<I>,
        S: HasCorpus<C, I>,
        C: Corpus<I>
    {
        let num = self.iterations(state);
        for i in 0..num {
            let mut input_mut = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            self.mutator_mut()
                .mutate(state, &mut input_mut, i as i32)?;

            let fitness = state.process_input(input_mut, executor, manager)?;

            self.mutator_mut().post_exec(state, fitness, i as i32)?;
        }
        Ok(())
    }
}

pub static DEFAULT_MUTATIONAL_MAX_ITERATIONS: u64 = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct StdMutationalStage<I, M>
where
    M: Mutator<I>,
    I: Input,
{
    mutator: M,
    phantom: PhantomData<I>,
}

impl<I, M> MutationalStage<I, M> for StdMutationalStage<I, M>
where
    M: Mutator<I>,
    I: Input,
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
    fn iterations<R, S>(&mut self, state: &mut S) -> usize
    where
        S: HasRand<R>,
        R: Rand
    {
        1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize
    }
}

impl<I, M> Stage<I> for StdMutationalStage<I, M>
where
    M: Mutator<I>,
    I: Input,
{
    #[inline]
    fn perform<E, EM, S, C>(
        &self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>
    where
        EM: EventManager<I>,
        E: Executor<I>,
        S: HasCorpus<C, I>,
        C: Corpus<I>
    {
        self.perform_mutational(executor, state, manager, corpus_idx)
    }
}

impl<I, M> StdMutationalStage<I, M>
where
    M: Mutator<I>,
    I: Input,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self {
            mutator: mutator,
            phantom: PhantomData,
        }
    }
}
