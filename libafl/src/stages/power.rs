//! The power schedules. This stage should be invoked after the calibration stage.

use core::{fmt::Debug, marker::PhantomData};

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    corpus::{Corpus, CorpusId},
    executors::{Executor, ExitKind, HasObservers},
    fuzzer::Evaluator,
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    schedulers::{
        ecofuzz::EcoTestcaseScore, testcase_score::CorpusPowerTestcaseScore, TestcaseScore,
    },
    stages::{
        mutational::{MutatedTransform, MutatedTransformPost},
        MutationalStage, Stage,
    },
    start_timer,
    state::{
        HasClientPerfMonitor, HasCorpus, HasCurrentStageInfo, HasMetadata, HasRand, UsesState,
    },
    Error,
};

/// The mutational stage using power schedules
#[derive(Clone, Debug)]
pub struct PowerMutationalStage<E, F, EM, I, M, MTP, Z> {
    mutator: M,
    limit: usize,
    corpus_idx: Option<CorpusId>,
    new_corpus_idx: Option<CorpusId>,
    post: Option<MTP>,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, F, EM, I, Z)>,
}

impl<E, F, EM, I, M, MTP, Z> UsesState for PowerMutationalStage<E, F, EM, I, M, MTP, Z>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E, F, EM, I, M, Z> MutationalStage<E, EM, I, M, Z>
    for PowerMutationalStage<E, F, EM, I, M, I::Post, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasClientPerfMonitor + HasCurrentStageInfo + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    I: MutatedTransform<E::Input, E::State> + Clone,
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
    #[allow(clippy::cast_sign_loss)]
    fn iterations(&self, state: &mut E::State, corpus_idx: CorpusId) -> Result<u64, Error> {
        // Update handicap
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let score = F::compute(state, &mut *testcase)? as u64;

        Ok(score)
    }
}

impl<E, F, EM, I, M, Z> Stage<E, EM, Z> for PowerMutationalStage<E, F, EM, I, M, I::Post, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasClientPerfMonitor + HasCurrentStageInfo + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
    I: MutatedTransform<E::Input, E::State> + Clone,
{
    type Context = I;
    #[inline]
    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<Option<Self::Context>, Error> {
        self.limit = self.iterations(state, corpus_idx)? as usize;
        self.corpus_idx = Some(corpus_idx);

        start_timer!(state);
        let mut testcase = state.corpus().get(corpus_idx)?.borrow_mut();
        let Ok(input) = Self::Context::try_transform_from(&mut testcase, state, corpus_idx) else { return Err(Error::unsupported("Couldn't transform testcase")); };
        drop(testcase);

        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
        Ok(Some(input))
    }

    #[inline]
    fn limit(&self) -> Result<usize, Error> {
        Ok(self.limit)
    }

    #[inline]
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: Self::Context,
        index: usize,
    ) -> Result<(Self::Context, bool), Error> {
        let mut input = input.clone();

        start_timer!(state);
        let mutated = self.mutator_mut().mutate(state, &mut input, index as i32)?;
        mark_feature_time!(state, PerfFeature::Mutate);

        if mutated == MutationResult::Skipped {
            Ok((input, false))
        } else {
            Ok((input, true))
        }
    }

    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: Self::Context,
        _index: usize,
    ) -> Result<(Self::Context, ExitKind), Error> {
        // Time is measured directly the `evaluate_input` function
        let (untransformed, post) = input.clone().try_transform_into(state)?;
        let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, untransformed)?;
        self.post = Some(post);
        self.new_corpus_idx = corpus_idx;
        Ok((input, ExitKind::Ok))
    }

    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: Self::Context,
        index: usize,
        _exit_kind: ExitKind,
    ) -> Result<(Self::Context, Option<usize>), Error> {
        start_timer!(state);
        let new_corpus_idx = self.new_corpus_idx;
        self.mutator_mut()
            .post_exec(state, index as i32, new_corpus_idx)?;
        if let Some(post) = self.post.as_mut() {
            post.clone()
                .post_exec(state, index as i32, new_corpus_idx)?;
        }
        mark_feature_time!(state, PerfFeature::MutatePostExec);
        Ok((input, None))
    }

    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        _state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, F, EM, M, MTP, Z> PowerMutationalStage<E, F, EM, E::Input, M, MTP, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<E::Input, E::State>,
    E::State: HasClientPerfMonitor + HasCurrentStageInfo + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// Creates a new [`PowerMutationalStage`]
    pub fn new(mutator: M) -> Self {
        Self::transforming(mutator)
    }
}

impl<E, F, EM, I, M, MTP, Z> PowerMutationalStage<E, F, EM, I, M, MTP, Z>
where
    E: Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    F: TestcaseScore<E::State>,
    M: Mutator<I, E::State>,
    E::State: HasClientPerfMonitor + HasCurrentStageInfo + HasCorpus + HasMetadata + HasRand,
    Z: Evaluator<E, EM, State = E::State>,
{
    /// Creates a new transforming [`PowerMutationalStage`]
    pub fn transforming(mutator: M) -> Self {
        Self {
            mutator,
            limit: 0,
            corpus_idx: None,
            new_corpus_idx: None,
            post: None,
            phantom: PhantomData,
        }
    }
}

/// The standard powerscheduling stage
pub type StdPowerMutationalStage<E, EM, I, M, MTP, Z> =
    PowerMutationalStage<E, CorpusPowerTestcaseScore<<E as UsesState>::State>, EM, I, M, MTP, Z>;

/// Ecofuzz scheduling stage
pub type EcoPowerMutationalStage<E, EM, I, M, MTP, Z> =
    PowerMutationalStage<E, EcoTestcaseScore<<E as UsesState>::State>, EM, I, M, MTP, Z>;
