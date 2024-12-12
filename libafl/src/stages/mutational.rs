//| The [`MutationalStage`] is the default stage used during fuzzing.
//! For the current input, it will perform a range of random mutations, and then run them in the executor.

use alloc::{
    borrow::{Cow, ToOwned},
    string::ToString,
};
use core::{marker::PhantomData, num::NonZeroUsize};

use libafl_bolts::{rands::Rand, Named};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, Testcase},
    fuzzer::Evaluator,
    inputs::{Input, UsesInput},
    mark_feature_time,
    mutators::{MultiMutator, MutationResult, Mutator},
    nonzero,
    stages::{RetryCountRestartHelper, Stage},
    start_timer,
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasRand, MaybeHasClientPerfMonitor},
    Error, HasMetadata, HasNamedMetadata,
};

// TODO multi mutators stage

/// Action performed after the un-transformed input is executed (e.g., updating metadata)
#[allow(unused_variables)]
pub trait MutatedTransformPost<S>: Sized {
    /// Perform any post-execution steps necessary for the transformed input (e.g., updating metadata)
    #[inline]
    fn post_exec(self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> MutatedTransformPost<S> for () {}

/// A type which may both be transformed from and into a given input type, used to perform
/// mutations over inputs which are not necessarily performable on the underlying type
///
/// This trait is implemented such that all testcases inherently transform to their inputs, should
/// the input be cloneable.
pub trait MutatedTransform<I, S>: Sized
where
    I: Input,
{
    /// Type indicating actions to be taken after the post-transformation input is executed
    type Post: MutatedTransformPost<S>;

    /// Transform the provided testcase into this type
    fn try_transform_from(base: &mut Testcase<I>, state: &S) -> Result<Self, Error>;

    /// Transform this instance back into the original input type
    fn try_transform_into(self, state: &S) -> Result<(I, Self::Post), Error>;
}

// reflexive definition
impl<I, S> MutatedTransform<I, S> for I
where
    I: Input + Clone,
    S: HasCorpus,
    S::Corpus: Corpus<Input = I>,
{
    type Post = ();

    #[inline]
    fn try_transform_from(base: &mut Testcase<I>, state: &S) -> Result<Self, Error> {
        state.corpus().load_input_into(base)?;
        Ok(base.input().as_ref().unwrap().clone())
    }

    #[inline]
    fn try_transform_into(self, _state: &S) -> Result<(I, Self::Post), Error> {
        Ok((self, ()))
    }
}

/// A Mutational stage is the stage in a fuzzing run that mutates inputs.
/// Mutational stages will usually have a range of mutations that are
/// being applied to the input one by one, between executions.
pub trait MutationalStage<S> {
    /// The mutator of this stage
    type Mutator;

    /// The mutator registered for this stage
    fn mutator(&self) -> &Self::Mutator;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut Self::Mutator;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut S) -> Result<usize, Error>;
}

/// Default value, how many iterations each stage gets, as an upper bound.
/// It may randomly continue earlier.
pub const DEFAULT_MUTATIONAL_MAX_ITERATIONS: usize = 128;

/// The default mutational stage
#[derive(Clone, Debug)]
pub struct StdMutationalStage<E, EM, I, M, S, Z> {
    /// The name
    name: Cow<'static, str>,
    /// The mutator(s) to use
    mutator: M,
    /// The maximum amount of iterations we should do each round
    max_iterations: NonZeroUsize,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, S, Z)>,
}

impl<E, EM, I, M, S, Z> MutationalStage<S> for StdMutationalStage<E, EM, I, M, S, Z>
where
    S: HasRand,
{
    type Mutator = M;

    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &Self::Mutator {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut Self::Mutator {
        &mut self.mutator
    }

    /// Gets the number of iterations as a random number
    fn iterations(&self, state: &mut S) -> Result<usize, Error> {
        Ok(1 + state.rand_mut().below(self.max_iterations))
    }
}

/// The unique id for mutational stage
static mut MUTATIONAL_STAGE_ID: usize = 0;
/// The name for mutational stage
pub static MUTATIONAL_STAGE_NAME: &str = "mutational";

impl<E, EM, I, M, S, Z> Named for StdMutationalStage<E, EM, I, M, S, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, I, M, S, Z> Stage<E, EM, S, Z> for StdMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    Z: Evaluator<E, EM, State = S>,
    S: HasCorpus
        + HasRand
        + HasMetadata
        + HasExecutions
        + HasNamedMetadata
        + HasCurrentCorpusId
        + MaybeHasClientPerfMonitor
        + UsesInput,
    I: MutatedTransform<<S::Corpus as Corpus>::Input, S> + Clone,
    <S::Corpus as Corpus>::Input: Input,
    S::Corpus: Corpus<Input = S::Input>,
{
    #[inline]
    #[allow(clippy::let_and_return)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let ret = self.perform_mutational(fuzzer, executor, state, manager);

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        ret
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<E, EM, M, S, Z> StdMutationalStage<E, EM, <S::Corpus as Corpus>::Input, M, S, Z>
where
    M: Mutator<<S::Corpus as Corpus>::Input, S>,
    Z: Evaluator<E, EM, State = S>,
    S: HasCorpus + HasRand + HasCurrentCorpusId + UsesInput + MaybeHasClientPerfMonitor,
    <S::Corpus as Corpus>::Input: Input + Clone,
    S::Corpus: Corpus<Input = S::Input>,
{
    /// Creates a new default mutational stage
    pub fn new(mutator: M) -> Self {
        // Safe to unwrap: DEFAULT_MUTATIONAL_MAX_ITERATIONS is never 0.
        Self::transforming_with_max_iterations(mutator, nonzero!(DEFAULT_MUTATIONAL_MAX_ITERATIONS))
    }

    /// Creates a new mutational stage with the given max iterations
    #[inline]
    pub fn with_max_iterations(mutator: M, max_iterations: NonZeroUsize) -> Self {
        Self::transforming_with_max_iterations(mutator, max_iterations)
    }
}

impl<E, EM, I, M, S, Z> StdMutationalStage<E, EM, I, M, S, Z>
where
    M: Mutator<I, S>,
    Z: Evaluator<E, EM, State = S>,
    S: HasCorpus + HasRand + HasCurrentTestcase + MaybeHasClientPerfMonitor + UsesInput,
    I: MutatedTransform<<S::Corpus as Corpus>::Input, S> + Clone,
    <S::Corpus as Corpus>::Input: Input,
    S::Corpus: Corpus<Input = S::Input>,
{
    /// Creates a new transforming mutational stage with the default max iterations
    pub fn transforming(mutator: M) -> Self {
        // Safe to unwrap: DEFAULT_MUTATIONAL_MAX_ITERATIONS is never 0.
        Self::transforming_with_max_iterations(mutator, nonzero!(DEFAULT_MUTATIONAL_MAX_ITERATIONS))
    }

    /// Creates a new transforming mutational stage with the given max iterations
    ///
    /// # Errors
    /// Will return [`Error::IllegalArgument`] for `max_iterations` of 0.
    #[inline]
    pub fn transforming_with_max_iterations(mutator: M, max_iterations: NonZeroUsize) -> Self {
        let stage_id = unsafe {
            let ret = MUTATIONAL_STAGE_ID;
            MUTATIONAL_STAGE_ID += 1;
            ret
        };
        let name =
            Cow::Owned(MUTATIONAL_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_str());
        Self {
            name,
            mutator,
            max_iterations,
            phantom: PhantomData,
        }
    }

    /// Runs this (mutational) stage for the given testcase
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_mutational(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        start_timer!(state);

        // Here saturating_sub is needed as self.iterations() might be actually smaller than the previous value before reset.
        /*
        let num = self
            .iterations(state)?
            .saturating_sub(self.execs_since_progress_start(state)?);
        */
        let num = self.iterations(state)?;
        let mut testcase = state.current_testcase_mut()?;

        let Ok(input) = I::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };
        drop(testcase);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        for _ in 0..num {
            let mut input = input.clone();

            start_timer!(state);
            let mutated = self.mutator_mut().mutate(state, &mut input)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            if mutated == MutationResult::Skipped {
                continue;
            }

            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = input.try_transform_into(state)?;
            let (_, corpus_id) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;

            start_timer!(state);
            self.mutator_mut().post_exec(state, corpus_id)?;
            post.post_exec(state, corpus_id)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }

        Ok(())
    }
}
/// A mutational stage that operates on multiple inputs, as returned by [`MultiMutator::multi_mutate`].
#[derive(Clone, Debug)]
pub struct MultiMutationalStage<E, EM, I, M, S, Z> {
    name: Cow<'static, str>,
    mutator: M,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, I, S, Z)>,
}

/// The unique id for multi mutational stage
static mut MULTI_MUTATIONAL_STAGE_ID: usize = 0;
/// The name for multi mutational stage
pub static MULTI_MUTATIONAL_STAGE_NAME: &str = "multimutational";

impl<E, EM, I, M, S, Z> Named for MultiMutationalStage<E, EM, I, M, S, Z> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<E, EM, I, M, S, Z> Stage<E, EM, S, Z> for MultiMutationalStage<E, EM, I, M, S, Z>
where
    M: MultiMutator<I, S>,
    Z: Evaluator<E, EM, State = S>,
    S: HasCorpus + HasRand + HasNamedMetadata + HasCurrentTestcase + HasCurrentCorpusId + UsesInput,
    I: MutatedTransform<<S::Corpus as Corpus>::Input, S> + Clone,
    <S::Corpus as Corpus>::Input: Input,
    S::Corpus: Corpus<Input = S::Input>,
{
    #[inline]
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        // Make sure we don't get stuck crashing on a single testcase
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    #[inline]
    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }

    #[inline]
    #[allow(clippy::let_and_return)]
    #[allow(clippy::cast_possible_wrap)]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let mut testcase = state.current_testcase_mut()?;
        let Ok(input) = I::try_transform_from(&mut testcase, state) else {
            return Ok(());
        };
        drop(testcase);

        let generated = self.mutator.multi_mutate(state, &input, None)?;
        // println!("Generated {}", generated.len());
        for new_input in generated {
            // Time is measured directly the `evaluate_input` function
            let (untransformed, post) = new_input.try_transform_into(state)?;
            let (_, corpus_id) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
            self.mutator.multi_post_exec(state, corpus_id)?;
            post.post_exec(state, corpus_id)?;
        }
        // println!("Found {}", found);

        Ok(())
    }
}

impl<E, EM, I, M, S, Z> MultiMutationalStage<E, EM, I, M, S, Z> {
    /// Creates a new [`MultiMutationalStage`]
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, EM, I, M, S, Z> MultiMutationalStage<E, EM, I, M, S, Z> {
    /// Creates a new transforming mutational stage
    pub fn transforming(mutator: M) -> Self {
        // unsafe but impossible that you create two threads both instantiating this instance
        let stage_id = unsafe {
            let ret = MULTI_MUTATIONAL_STAGE_ID;
            MULTI_MUTATIONAL_STAGE_ID += 1;
            ret
        };
        Self {
            name: Cow::Owned(
                MULTI_MUTATIONAL_STAGE_NAME.to_owned() + ":" + stage_id.to_string().as_str(),
            ),
            mutator,
            phantom: PhantomData,
        }
    }
}
