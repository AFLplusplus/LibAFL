//! The [`TMinMutationalStage`] is a stage which will attempt to minimize corpus entries.

use alloc::string::{String, ToString};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use ahash::AHasher;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::{tuples::Named, HasLen},
    corpus::{Corpus, Testcase},
    events::EventFirer,
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{Feedback, FeedbackFactory, HasObserverName},
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    observers::{MapObserver, ObserversTuple},
    schedulers::Scheduler,
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMaxSize},
    Error, ExecutesInput, ExecutionProcessor, HasFeedback, HasScheduler,
};

/// Mutational stage which minimizes corpus entries.
///
/// You must provide at least one mutator that actually reduces size.
pub trait TMinMutationalStage<F1, F2, I, M, OT, S, Z>:
    Stage + FeedbackFactory<F2, I, S, OT>
where
    Self::Executor: Executor + HasObservers,
    Self::EventManager: EventFirer,
    F1: Feedback,
    F2: Feedback,
    Self::Input: Input + Hash + HasLen,
    Self::State: HasClientPerfMonitor + HasCorpus + HasExecutions + HasMaxSize,
    Self::Fuzzer: ExecutionProcessor + ExecutesInput + HasFeedback + HasScheduler,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error>;

    /// Runs this (mutational) stage for new objectives
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_minification(
        &mut self,
        fuzzer: &mut Self::Fuzzer,
        executor: &mut Self::Executor,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
        base_corpus_idx: usize,
    ) -> Result<(), Error> {
        let orig_max_size = state.max_size();
        // basically copy-pasted from mutational.rs
        let num = self.iterations(state, base_corpus_idx)?;

        start_timer!(state);
        let mut base = state
            .corpus()
            .get(base_corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();
        let mut hasher = AHasher::new_with_keys(0, 0);
        base.hash(&mut hasher);
        let base_hash = hasher.finish();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        fuzzer.execute_input(state, executor, manager, &base)?;
        let observers = executor.observers();

        let mut feedback = self.create_feedback(observers);

        let mut i = 0;
        loop {
            if i >= num {
                break;
            }

            let mut next_i = i + 1;
            let mut input = base.clone();

            let before_len = input.len();

            state.set_max_size(before_len);

            start_timer!(state);
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            let corpus_idx = if input.len() < before_len {
                // run the input
                let exit_kind = fuzzer.execute_input(state, executor, manager, &input)?;
                let observers = executor.observers();

                // let the fuzzer process this execution -- it's possible that we find something
                // interesting, or even a solution
                let (_, corpus_idx) = fuzzer.process_execution(
                    state,
                    manager,
                    input.clone(),
                    observers,
                    &exit_kind,
                    false,
                )?;

                if feedback.is_interesting(state, manager, &input, observers, &exit_kind)? {
                    // we found a reduced corpus entry! use the smaller base
                    base = input;

                    // do more runs! maybe we can minify further
                    next_i = 0;
                }

                corpus_idx
            } else {
                // we can't guarantee that the mutators provided will necessarily reduce size, so
                // skip any mutations that actually increase size so we don't waste eval time
                None
            };

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);

            i = next_i;
        }

        let mut hasher = AHasher::new_with_keys(0, 0);
        base.hash(&mut hasher);
        let new_hash = hasher.finish();
        if base_hash != new_hash {
            let mut testcase = Testcase::with_executions(base, *state.executions());
            fuzzer
                .feedback_mut()
                .append_metadata(state, &mut testcase)?;
            let prev = state.corpus_mut().replace(base_corpus_idx, testcase)?;
            fuzzer
                .scheduler_mut()
                .on_replace(state, base_corpus_idx, &prev)?;
        }

        state.set_max_size(orig_max_size);

        Ok(())
    }
}

/// The default corpus entry minimising mutational stage
#[derive(Clone, Debug)]
pub struct StdTMinMutationalStage<F1, F2, FF, M>
where
    <Self as Stage>::Executor: Executor + HasObservers,
    <Self as Stage>::EventManager: EventFirer,
    F1: Feedback,
    F2: Feedback,
    FF: FeedbackFactory<
        F2,
        <Self as Stage>::Input,
        <Self as Stage>::State,
        <<Self as Stage>::Executor as HasObservers>::Observers,
    >,
    <Self as Stage>::Input: Input + Hash + HasLen,
    <Self as Stage>::State: HasClientPerfMonitor + HasCorpus + HasExecutions + HasMaxSize,
    <Self as Stage>::Fuzzer: ExecutionProcessor + ExecutesInput + HasFeedback + HasScheduler,
{
    mutator: M,
    factory: FF,
    runs: usize,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(F1, F2)>,
}

impl<F1, F2, FF, M> Stage for StdTMinMutationalStage<F1, F2, FF, M>
where
    Self::Executor: Executor + HasObservers,
    Self::EventManager: EventFirer,
    F1: Feedback,
    F2: Feedback,
    FF: FeedbackFactory<
        F2,
        Self::Input,
        Self::State,
        <<Self as Stage>::Executor as HasObservers>::Observers,
    >,
    Self::Input: Input + Hash + HasLen,
    Self::State: HasClientPerfMonitor + HasCorpus + HasExecutions + HasMaxSize,
    Self::Fuzzer: ExecutionProcessor + ExecutesInput + HasFeedback + HasScheduler,
{
    fn perform(
        &mut self,
        fuzzer: &mut Self::Fuzzer,
        executor: &mut Self::Executor,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.perform_minification(fuzzer, executor, state, manager, corpus_idx)?;

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        Ok(())
    }
}

impl<F1, F2, FF, I, M, S, T> FeedbackFactory<F2, I, S, T> for StdTMinMutationalStage<F1, F2, FF, M>
where
    F2: Feedback,
    FF: FeedbackFactory<F2, <Self as Stage>::Input, <Self as Stage>::State, T>,
    <Self as Stage>::Input: Input + HasLen,
    <Self as Stage>::State: HasClientPerfMonitor,
    M: Mutator<Input = <Self as Stage>::Input, State = <Self as Stage>::State>,
    S: HasClientPerfMonitor,
    Self: Stage<Input = I, State = S>,
{
    fn create_feedback(&self, ctx: &T) -> F2 {
        self.factory.create_feedback(ctx)
    }
}

impl<F1, F2, FF, I, M, OT, S, Z> TMinMutationalStage<F1, F2, I, M, OT, S, Z>
    for StdTMinMutationalStage<F1, F2, FF, M>
where
    Self::Executor: HasObservers + Executor,
    Self::EventManager: EventFirer,
    F1: Feedback<Input = Self::Input>,
    F2: Feedback<Input = Self::Input>,
    FF: FeedbackFactory<F2, I, S, OT>,
    I: Input + HasLen + Hash,
    Self: Stage<Input = I, State = S, Fuzzer = Z>,
    Self::Executor: HasObservers<Observers = OT>,
    M: Mutator<Input = I, State = S>,
    OT: ObserversTuple<Input = I, State = S>,
    S: HasClientPerfMonitor + HasCorpus + HasExecutions + HasMaxSize,
    Z: ExecutionProcessor<Input = I, Observers = OT>
        + ExecutesInput<Input = I, State = S, Fuzzer = Z>
        + HasFeedback<Feedback = F1>
        + HasScheduler,
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

impl<F1, F2, FF, M> StdTMinMutationalStage<F1, F2, FF, M>
where
    <Self as Stage>::Input: HasLen,
    M: Mutator<Input = <Self as Stage>::Input, State = <Self as Stage>::State>,
{
    /// Creates a new minimising mutational stage that will minimize provided corpus entries
    pub fn new(mutator: M, factory: FF, runs: usize) -> Self {
        Self {
            mutator,
            factory,
            runs,
            phantom: PhantomData,
        }
    }
}

/// A feedback which checks if the hash of the currently observed map is equal to the original hash
/// provided
#[derive(Clone, Debug)]
pub struct MapEqualityFeedback<M> {
    name: String,
    obs_name: String,
    orig_hash: u64,
    phantom: PhantomData<M>,
}

impl<M> MapEqualityFeedback<M> {
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

impl<M> Named for MapEqualityFeedback<M> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<M> HasObserverName for MapEqualityFeedback<M> {
    fn observer_name(&self) -> &str {
        &self.obs_name
    }
}

impl<M> Feedback for MapEqualityFeedback<M>
where
    M: MapObserver,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: &Self::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer,
        OT: ObserversTuple,
    {
        let obs = observers
            .match_name::<M>(self.observer_name())
            .expect("Should have been provided valid observer name.");
        Ok(obs.hash() == self.orig_hash)
    }
}

/// A feedback factory for ensuring that the maps for minimized inputs are the same
#[derive(Debug, Clone)]
pub struct MapEqualityFactory<M> {
    obs_name: String,
    phantom: PhantomData<M>,
}

impl<M> MapEqualityFactory<M>
where
    M: MapObserver,
{
    /// Creates a new map equality feedback for the given observer
    pub fn new_from_observer(obs: &M) -> Self {
        Self {
            obs_name: obs.name().to_string(),
            phantom: PhantomData,
        }
    }
}

impl<M> HasObserverName for MapEqualityFactory<M> {
    fn observer_name(&self) -> &str {
        &self.obs_name
    }
}

impl<I, M, OT, S> FeedbackFactory<MapEqualityFeedback<M>, I, S, OT> for MapEqualityFactory<M>
where
    M: MapObserver,
    OT: ObserversTuple,
    I: Input,
    S: HasClientPerfMonitor,
{
    fn create_feedback(&self, observers: &OT) -> MapEqualityFeedback<M> {
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
