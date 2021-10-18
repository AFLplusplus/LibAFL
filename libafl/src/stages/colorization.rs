use core::marker::PhantomData;

use crate::{
    bolts::rands::Rand,
    corpus::Corpus,
    fuzzer::Evaluator,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    stages::{mutational::{DEFAULT_MUTATIONAL_MAX_ITERATIONS, MutationalStage}, Stage},
    start_timer,
    state::{HasClientPerfStats, HasCorpus, HasRand},
    Error,
};

#[cfg(feature = "introspection")]
use crate::stats::PerfFeature;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct ColorizedMutationalStage<C, E, EM, I, M, R, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>,
{
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(C, E, EM, I, R, S, Z)>,
}

impl<C, E, EM, I, M, R, S, Z> MutationalStage<C, E, EM, I, M, S, Z>
    for ColorizedMutationalStage<C, E, EM, I, M, R, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
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
    fn iterations(&self, state: &mut S, _corpus_idx: usize) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(DEFAULT_MUTATIONAL_MAX_ITERATIONS) as usize)
    }
    
    #[allow(clippy::cast_possible_wrap)]
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        start_timer!(state);
        let mut colorized = state
            .corpus()
            .get(corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        self.colorize(&mut colorized)?;

        let num = self.iterations(state, corpus_idx)?;

        for i in 0..num {
            let input = colorized.clone();
            start_timer!(state);
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            // Time is measured directly the `evaluate_input` function
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }
        Ok(())
    }
}

impl<C, E, EM, I, M, R, S, Z> Stage<E, EM, S, Z> for ColorizedMutationalStage<C, E, EM, I, M, R, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
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

        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().finish_stage();

        ret
    }
}

impl<C, E, EM, I, M, R, S, Z> ColorizedMutationalStage<C, E, EM, I, M, R, S, Z>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        Self {
            mutator,
            phantom: PhantomData,
        }
    }
    
    pub fn colorize(input: &mut I) -> Result<(), Error> {
        
    }
}
