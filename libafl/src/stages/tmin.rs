//! The [`TMinMutationalStage`] is a stage which will attempt to minimise recent solutions.
//! For new solutions, it will perform a range of random mutations, and then run them in the executor.

use std::marker::PhantomData;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
pub use crate::stages::mutational::DEFAULT_MUTATIONAL_MAX_ITERATIONS;
use crate::{
    bolts::HasLen,
    corpus::Corpus,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasRand, HasSolutions},
    Error, Evaluator, ExecuteInputResult,
};

/// Mutational stage which minimises recent solutions.
///
/// This analysis is BYOM: Bring Your Own Mutators. You must provide at least one mutator that
/// actually reduces size, or implementations will infinitely loop.
pub trait TMinMutationalStage<E, EM, I, M, S, Z>: Stage<E, EM, S, Z>
where
    M: Mutator<I, S>,
    I: Input + HasLen,
    S: HasClientPerfMonitor + HasCorpus<I> + HasSolutions<I>,
    Z: Evaluator<E, EM, I, S>,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error>;

    /// Runs this (mutational) stage for new objectives
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        solution_idx: usize,
    ) -> Result<(), Error> {
        // basically copy-pasted from mutational.rs
        let num = self.iterations(state, solution_idx)?;

        start_timer!(state);
        let mut base = state
            .solutions()
            .get(solution_idx)?
            .borrow_mut()
            .load_input()?
            .clone();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        let mut i = 0;
        loop {
            if i >= num {
                break;
            }

            let mut next_i = i;
            let mut input = base.clone();

            let before_len = input.len();

            start_timer!(state);
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            let (res, corpus_idx) = if input.len() < before_len {
                // inform that our mutational step did actually reduce the length
                // possible infinite loop if the only mutations provided are same- or increasing-
                // size, but hopefully that doesn't happen :))
                next_i += 1;
                // Time is measured directly the `evaluate_input` function
                fuzzer.evaluate_input(state, executor, manager, input.clone())?
            } else {
                // we can't guarantee that the mutators provided will necessarily reduce size, so
                // skip any mutations that actually increase size so we don't waste eval time
                (ExecuteInputResult::None, None)
            };

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);

            if res == ExecuteInputResult::Solution {
                // we found a new solution! use the smaller base
                base = input;
            }

            i = next_i;
        }

        // return the minimised value -- could be useful
        Ok(())
    }
}

/// The default solution minimising mutational stage
#[derive(Clone, Debug)]
pub struct StdTMinMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input + HasLen,
    S: HasClientPerfMonitor + HasCorpus<I> + HasSolutions<I>,
    Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    runs: usize,
    next_solution: usize,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, S, Z)>,
}

impl<E, EM, I, M, S, Z> Stage<E, EM, S, Z> for StdTMinMutationalStage<E, EM, I, M, S, Z>
where
    I: Input + HasLen,
    M: Mutator<I, S>,
    S: HasClientPerfMonitor + HasCorpus<I> + HasSolutions<I>,
    Z: Evaluator<E, EM, I, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        _: usize,
    ) -> Result<(), Error> {
        let end = state.solutions().count();

        for solution_idx in self.next_solution..end {
            self.perform_mutational(fuzzer, executor, state, manager, solution_idx)?;
        }

        // skip entries that we've already minimised
        self.next_solution = state.solutions().count();

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        Ok(())
    }
}

impl<E, EM, I, M, S, Z> TMinMutationalStage<E, EM, I, M, S, Z>
    for StdTMinMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input + HasLen,
    S: HasClientPerfMonitor + HasCorpus<I> + HasSolutions<I>,
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

    /// Gets the number of iterations from a fixed number of runs
    fn iterations(&self, _state: &mut S, _corpus_idx: usize) -> Result<usize, Error> {
        Ok(self.runs)
    }
}

impl<E, EM, I, M, S, Z> StdTMinMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    I: Input + HasLen,
    S: HasClientPerfMonitor + HasCorpus<I> + HasSolutions<I> + HasRand,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new minimising mutational stage, assuming that we will not minimise existing
    /// solutions (best for fuzzers that have already minimised existing solutions)
    pub fn new_with_state(mutator: M, state: &S, runs: usize) -> Self {
        Self {
            mutator,
            runs,
            next_solution: state.solutions().count(),
            phantom: PhantomData,
        }
    }

    /// Creates a new minimising mutational stage that will minimise existing solutions
    pub fn new(mutator: M, runs: usize) -> Self {
        Self {
            mutator,
            runs,
            next_solution: 0,
            phantom: PhantomData,
        }
    }
}
