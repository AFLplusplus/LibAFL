//! The [`TMinMutationalStage`] is a stage which will attempt to minimize corpus entries.

use alloc::string::{String, ToString};
use core::{
    fmt::Debug,
    hash::{BuildHasher, Hash, Hasher},
    marker::PhantomData,
};

use ahash::RandomState;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::{tuples::Named, HasLen},
    corpus::{Corpus, CorpusId, Testcase},
    events::EventFirer,
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{Feedback, FeedbackFactory, HasObserverName},
    inputs::UsesInput,
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    observers::{MapObserver, ObserversTuple},
    schedulers::{RemovableScheduler, Scheduler},
    stages::Stage,
    start_timer,
    state::{
        HasClientPerfMonitor, HasCorpus, HasCurrentStageInfo, HasExecutions, HasMaxSize,
        HasSolutions, UsesState,
    },
    Error, ExecutesInput, ExecutionProcessor, HasFeedback, HasScheduler,
};

/// Mutational stage which minimizes corpus entries.
///
/// You must provide at least one mutator that actually reduces size.
pub trait TMinMutationalStage<CS, E, EM, F1, F2, M, OT, Z>:
    Stage<E, EM, Z> + FeedbackFactory<F2, CS::State, OT>
where
    Self::State: HasCorpus
        + HasCurrentStageInfo
        + HasSolutions
        + HasExecutions
        + HasMaxSize
        + HasClientPerfMonitor,
    <Self::State as UsesInput>::Input: HasLen + Hash,
    CS: Scheduler<State = Self::State> + RemovableScheduler,
    E: Executor<EM, Z> + HasObservers<Observers = OT, State = Self::State>,
    EM: EventFirer<State = Self::State>,
    F1: Feedback<Self::State>,
    F2: Feedback<Self::State>,
    M: Mutator<Self::Input, Self::State>,
    OT: ObserversTuple<CS::State>,
    Z: ExecutionProcessor<OT, State = Self::State>
        + ExecutesInput<E, EM>
        + HasFeedback<Feedback = F1>
        + HasScheduler<Scheduler = CS>,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut CS::State, corpus_idx: CorpusId) -> Result<usize, Error>;
}

/// The default corpus entry minimising mutational stage
#[derive(Clone, Debug)]
pub struct StdTMinMutationalStage<CS, E, EM, F1, F2, FF, M, OT, Z> {
    mutator: M,
    factory: FF,
    limit: usize,
    base_hash: u64,
    feedback: Option<F2>,
    corpus_idx: Option<CorpusId>,
    orig_max_size: usize,
    runs: usize,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(CS, E, EM, F1, F2, OT, Z)>,
}

impl<CS, E, EM, F1, F2, FF, M, OT, Z> UsesState
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, M, OT, Z>
where
    CS: Scheduler,
    M: Mutator<CS::Input, CS::State>,
    Z: ExecutionProcessor<OT, State = CS::State>,
    CS::State: HasCorpus + HasCurrentStageInfo,
{
    type State = CS::State;
}

impl<CS, E, EM, F1, F2, FF, M, OT, Z> Stage<E, EM, Z>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, M, OT, Z>
where
    CS: Scheduler + RemovableScheduler,
    CS::State: HasCorpus
        + HasCurrentStageInfo
        + HasSolutions
        + HasExecutions
        + HasMaxSize
        + HasClientPerfMonitor
        + HasCorpus,
    <CS::State as UsesInput>::Input: HasLen + Hash,
    E: Executor<EM, Z> + HasObservers<Observers = OT, State = CS::State>,
    EM: EventFirer<State = CS::State>,
    F1: Feedback<CS::State>,
    F2: Feedback<CS::State>,
    FF: FeedbackFactory<F2, CS::State, OT>,
    M: Mutator<CS::Input, CS::State>,
    OT: ObserversTuple<CS::State>,
    Z: ExecutionProcessor<OT, State = CS::State>
        + ExecutesInput<E, EM>
        + HasFeedback<Feedback = F1>
        + HasScheduler<Scheduler = CS>,
{
    type Context = Self::Input;
    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<E::Input, Error> {
        self.orig_max_size = state.max_size();
        // basically copy-pasted from mutational.rs
        self.limit = self.iterations(state, corpus_idx)? + 1;
        self.corpus_idx = Some(corpus_idx);

        start_timer!(state);
        let base = state.corpus().cloned_input_for_id(corpus_idx)?;
        let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        base.hash(&mut hasher);
        self.base_hash = hasher.finish();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);
        Ok(base)
    }

    fn limit(&self) -> Result<usize, Error> {
        Ok(self.limit)
    }

    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
        input: E::Input,
        index: usize,
    ) -> Result<(E::Input, bool), Error> {
        if index == self.limit()? {
            let mut hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
            input.hash(&mut hasher);
            let new_hash = hasher.finish();
            if self.base_hash != new_hash {
                Ok((input, true))
            } else {
                Ok((input, false))
            }
        } else {
            if index != 0 {
                let mut input = input.clone();

                let before_len = input.len();

                state.set_max_size(before_len);

                start_timer!(state);
                let mutated = self.mutator_mut().mutate(state, &mut input, index as i32)?;
                mark_feature_time!(state, PerfFeature::Mutate);

                if mutated == MutationResult::Skipped || input.len() >= before_len {
                    Ok((input, false))
                } else {
                    Ok((input, true))
                }
            } else {
                Ok((input, true))
            }
        }
    }

    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: E::Input,
        _index: usize,
    ) -> Result<(E::Input, ExitKind), Error> {
        let exit_kind = fuzzer.execute_input(state, executor, manager, &input)?;
        Ok((input, exit_kind))
    }

    fn post_exec(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
        input: E::Input,
        index: usize,
        exit_kind: ExitKind,
    ) -> Result<(E::Input, Option<usize>), Error> {
        if index == self.limit()? {
            let observers = executor.observers();
            *state.executions_mut() += 1;
            // assumption: this input should not be marked interesting because it was not
            // marked as interesting above; similarly, it should not trigger objectives
            fuzzer
                .feedback_mut()
                .is_interesting(state, manager, &input, observers, &exit_kind)?;
            let mut testcase = Testcase::with_executions(input.clone(), *state.executions());
            fuzzer
                .feedback_mut()
                .append_metadata(state, observers, &mut testcase)?;
            let prev = state
                .corpus_mut()
                .replace(self.corpus_idx.unwrap(), testcase)?;
            fuzzer
                .scheduler_mut()
                .on_replace(state, self.corpus_idx.unwrap(), &prev)?;

            state.set_max_size(self.orig_max_size);
            Ok((input, Some(self.limit()? + 1)))
        } else {
            let result = if index != 0 {
                let observers = executor.observers();

                // let the fuzzer process this execution -- it's possible that we find something
                // interesting, or even a solution

                // TODO replace if process_execution adds a return value for solution index
                let solution_count = state.solutions().count();
                let corpus_count = state.corpus().count();
                *state.executions_mut() += 1;
                let (_, corpus_idx) = fuzzer.process_execution(
                    state,
                    manager,
                    input.clone(),
                    observers,
                    &exit_kind,
                    false,
                )?;

                self.corpus_idx = corpus_idx;
                if state.corpus().count() == corpus_count
                    && state.solutions().count() == solution_count
                {
                    // we do not care about interesting inputs!
                    if self
                        .feedback
                        .as_mut()
                        .unwrap()
                        .is_interesting(state, manager, &input, observers, &exit_kind)?
                    {
                        // we found a reduced corpus entry! use the smaller base
                        // do more runs! maybe we can minify further
                        Ok((input, Some(0)))
                    } else {
                        Ok((input, None))
                    }
                } else {
                    Ok((input, None))
                }
            } else {
                self.feedback = Some(self.create_feedback(executor.observers()));
                self.corpus_idx = None;
                Ok((input, None))
            };
            start_timer!(state);
            let corpus_idx = self.corpus_idx;
            self.mutator_mut()
                .post_exec(state, index as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
            result
        }
    }

    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Self::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();
        Ok(())
    }
}

impl<CS, E, EM, F1, F2, FF, M, OT, Z> FeedbackFactory<F2, Z::State, OT>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, M, OT, Z>
where
    F2: Feedback<Z::State>,
    FF: FeedbackFactory<F2, Z::State, OT>,
    Z: UsesState,
    Z::State: HasClientPerfMonitor,
{
    fn create_feedback(&self, ctx: &OT) -> F2 {
        self.factory.create_feedback(ctx)
    }
}

impl<CS, E, EM, F1, F2, FF, M, OT, Z> TMinMutationalStage<CS, E, EM, F1, F2, M, OT, Z>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, M, OT, Z>
where
    CS: Scheduler + RemovableScheduler,
    E: HasObservers<Observers = OT, State = CS::State> + Executor<EM, Z>,
    EM: EventFirer<State = CS::State>,
    F1: Feedback<CS::State>,
    F2: Feedback<CS::State>,
    FF: FeedbackFactory<F2, CS::State, OT>,
    <CS::State as UsesInput>::Input: HasLen + Hash,
    M: Mutator<CS::Input, CS::State>,
    OT: ObserversTuple<CS::State>,
    CS::State: HasClientPerfMonitor
        + HasCurrentStageInfo
        + HasCorpus
        + HasSolutions
        + HasExecutions
        + HasMaxSize,
    Z: ExecutionProcessor<OT, State = CS::State>
        + ExecutesInput<E, EM>
        + HasFeedback<Feedback = F1>
        + HasScheduler<Scheduler = CS>,
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
    fn iterations(&self, _state: &mut CS::State, _corpus_idx: CorpusId) -> Result<usize, Error> {
        Ok(self.runs)
    }
}

impl<CS, E, EM, F1, F2, FF, M, OT, Z> StdTMinMutationalStage<CS, E, EM, F1, F2, FF, M, OT, Z>
where
    CS: Scheduler,
    M: Mutator<CS::Input, CS::State>,
    Z: ExecutionProcessor<OT, State = CS::State>,
    CS::State: HasCorpus,
{
    /// Creates a new minimising mutational stage that will minimize provided corpus entries
    pub fn new(mutator: M, factory: FF, runs: usize) -> Self {
        Self {
            mutator,
            factory,
            limit: 0,
            base_hash: 0,
            feedback: None,
            corpus_idx: None,
            orig_max_size: 0,
            runs,
            phantom: PhantomData,
        }
    }
}

/// A feedback which checks if the hash of the currently observed map is equal to the original hash
/// provided
#[derive(Clone, Debug)]
pub struct MapEqualityFeedback<M, S> {
    name: String,
    obs_name: String,
    orig_hash: u64,
    phantom: PhantomData<(M, S)>,
}

impl<M, S> MapEqualityFeedback<M, S> {
    /// Create a new map equality feedback -- can be used with feedback logic
    #[must_use]
    pub fn new(name: &str, obs_name: &str, orig_hash: u64) -> Self {
        MapEqualityFeedback {
            name: name.to_string(),
            obs_name: obs_name.to_string(),
            orig_hash,
            phantom: PhantomData,
        }
    }
}

impl<M, S> Named for MapEqualityFeedback<M, S> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<M, S> HasObserverName for MapEqualityFeedback<M, S> {
    fn observer_name(&self) -> &str {
        &self.obs_name
    }
}

impl<M, S> Feedback<S> for MapEqualityFeedback<M, S>
where
    M: MapObserver + Debug,
    S: UsesInput + HasClientPerfMonitor + Debug,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let obs = observers
            .match_name::<M>(self.observer_name())
            .expect("Should have been provided valid observer name.");
        Ok(obs.hash() == self.orig_hash)
    }
}

/// A feedback factory for ensuring that the maps for minimized inputs are the same
#[derive(Debug, Clone)]
pub struct MapEqualityFactory<M, S> {
    obs_name: String,
    phantom: PhantomData<(M, S)>,
}

impl<M, S> MapEqualityFactory<M, S>
where
    M: MapObserver,
{
    /// Creates a new map equality feedback for the given observer
    pub fn with_observer(obs: &M) -> Self {
        Self {
            obs_name: obs.name().to_string(),
            phantom: PhantomData,
        }
    }
}

impl<M, S> HasObserverName for MapEqualityFactory<M, S> {
    fn observer_name(&self) -> &str {
        &self.obs_name
    }
}

impl<M, OT, S> FeedbackFactory<MapEqualityFeedback<M, S>, S, OT> for MapEqualityFactory<M, S>
where
    M: MapObserver,
    OT: ObserversTuple<S>,
    S: UsesInput + HasClientPerfMonitor + Debug,
{
    fn create_feedback(&self, observers: &OT) -> MapEqualityFeedback<M, S> {
        let obs = observers
            .match_name::<M>(self.observer_name())
            .expect("Should have been provided valid observer name.");
        MapEqualityFeedback {
            name: "MapEq".to_string(),
            obs_name: self.obs_name.clone(),
            orig_hash: obs.hash(),
            phantom: PhantomData,
        }
    }
}
