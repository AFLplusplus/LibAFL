//! The [`TMinMutationalStage`] is a stage which will attempt to minimize corpus entries.

use alloc::borrow::Cow;
use core::{borrow::BorrowMut, fmt::Debug, hash::Hash, marker::PhantomData};

use ahash::RandomState;
use libafl_bolts::{
    tuples::{Handle, Handled, MatchNameRef},
    HasLen, Named,
};

use crate::{
    corpus::{Corpus, HasCurrentCorpusIdx, Testcase},
    events::EventFirer,
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{Feedback, FeedbackFactory, HasObserverHandle},
    inputs::UsesInput,
    mark_feature_time,
    mutators::{MutationResult, Mutator},
    observers::{MapObserver, ObserversTuple},
    schedulers::{RemovableScheduler, Scheduler},
    stages::{
        mutational::{MutatedTransform, MutatedTransformPost},
        ExecutionCountRestartHelper, Stage,
    },
    start_timer,
    state::{
        HasCorpus, HasCurrentTestcase, HasExecutions, HasMaxSize, HasSolutions, State, UsesState,
    },
    Error, ExecutesInput, ExecutionProcessor, HasFeedback, HasMetadata, HasScheduler,
};
#[cfg(feature = "introspection")]
use crate::{monitors::PerfFeature, state::HasClientPerfMonitor};

/// Mutational stage which minimizes corpus entries.
///
/// You must provide at least one mutator that actually reduces size.
pub trait TMinMutationalStage<CS, E, EM, F1, F2, I, IP, M, OT, Z>:
    Stage<E, EM, Z> + FeedbackFactory<F2, CS::State, OT>
where
    Self::State: HasCorpus + HasSolutions + HasExecutions + HasMaxSize,
    <Self::State as UsesInput>::Input: HasLen + Hash,
    CS: Scheduler<State = Self::State> + RemovableScheduler,
    E: Executor<EM, Z> + HasObservers<Observers = OT, State = Self::State>,
    EM: EventFirer<State = Self::State>,
    F1: Feedback<Self::State>,
    F2: Feedback<Self::State>,
    M: Mutator<I, Self::State>,
    OT: ObserversTuple<CS::State>,
    Z: ExecutionProcessor<OT, State = Self::State>
        + ExecutesInput<E, EM>
        + HasFeedback<Feedback = F1>
        + HasScheduler<Scheduler = CS>,
    IP: MutatedTransformPost<Self::State> + Clone,
    I: MutatedTransform<Self::Input, Self::State, Post = IP> + Clone,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut CS::State) -> Result<usize, Error>;

    /// Runs this (mutational) stage for new objectives
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_minification(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut CS::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let Some(base_corpus_idx) = state.current_corpus_idx()? else {
            return Err(Error::illegal_state(
                "state is not currently processing a corpus index",
            ));
        };

        let orig_max_size = state.max_size();
        // basically copy-pasted from mutational.rs
        let num = self.iterations(state)?
            - usize::try_from(self.execs_since_progress_start(state)?).unwrap();

        start_timer!(state);
        let transformed = I::try_transform_from(state.current_testcase_mut()?.borrow_mut(), state)?;
        let mut base = state.current_input_cloned()?;
        // potential post operation if base is replaced by a shorter input
        let mut base_post = None;
        let base_hash = RandomState::with_seeds(0, 0, 0, 0).hash_one(&base);
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        fuzzer.execute_input(state, executor, manager, &base)?;
        let observers = executor.observers();

        let mut feedback = self.create_feedback(&*observers);

        let mut i = 0;
        loop {
            if i >= num {
                break;
            }

            let mut next_i = i + 1;
            let mut input_transformed = transformed.clone();

            let before_len = base.len();

            state.set_max_size(before_len);

            start_timer!(state);
            let mutated = self.mutator_mut().mutate(state, &mut input_transformed)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            if mutated == MutationResult::Skipped {
                continue;
            }

            let (input, post) = input_transformed.try_transform_into(state)?;
            let corpus_idx = if input.len() < before_len {
                // run the input
                let exit_kind = fuzzer.execute_input(state, executor, manager, &input)?;
                let observers = executor.observers();

                // let the fuzzer process this execution -- it's possible that we find something
                // interesting, or even a solution

                // TODO replace if process_execution adds a return value for solution index
                let solution_count = state.solutions().count();
                let corpus_count = state.corpus().count();
                let (_, corpus_idx) = fuzzer.execute_and_process(
                    state,
                    manager,
                    input.clone(),
                    &*observers,
                    &exit_kind,
                    false,
                )?;

                if state.corpus().count() == corpus_count
                    && state.solutions().count() == solution_count
                {
                    // we do not care about interesting inputs!
                    if feedback.is_interesting(state, manager, &input, &*observers, &exit_kind)? {
                        // we found a reduced corpus entry! use the smaller base
                        base = input;
                        base_post = Some(post.clone());

                        // do more runs! maybe we can minify further
                        next_i = 0;
                    }
                }

                corpus_idx
            } else {
                // we can't guarantee that the mutators provided will necessarily reduce size, so
                // skip any mutations that actually increase size so we don't waste eval time
                None
            };

            start_timer!(state);
            self.mutator_mut().post_exec(state, corpus_idx)?;
            post.post_exec(state, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);

            i = next_i;
        }

        let new_hash = RandomState::with_seeds(0, 0, 0, 0).hash_one(&base);
        if base_hash != new_hash {
            let exit_kind = fuzzer.execute_input(state, executor, manager, &base)?;
            let observers = executor.observers();
            // assumption: this input should not be marked interesting because it was not
            // marked as interesting above; similarly, it should not trigger objectives
            fuzzer
                .feedback_mut()
                .is_interesting(state, manager, &base, &*observers, &exit_kind)?;
            let mut testcase = Testcase::with_executions(base, *state.executions());
            fuzzer
                .feedback_mut()
                .append_metadata(state, manager, &*observers, &mut testcase)?;
            let prev = state.corpus_mut().replace(base_corpus_idx, testcase)?;
            fuzzer
                .scheduler_mut()
                .on_replace(state, base_corpus_idx, &prev)?;
            // perform the post operation for the new testcase, e.g. to update metadata.
            // base_post should be updated along with the base (and is no longer None)
            base_post
                .ok_or_else(|| Error::empty_optional("Failed to get the MutatedTransformPost"))?
                .post_exec(state, Some(base_corpus_idx))?;
        }

        state.set_max_size(orig_max_size);

        Ok(())
    }

    /// Gets the number of executions this mutator already did since it got first called in this fuzz round.
    fn execs_since_progress_start(&mut self, state: &mut Z::State) -> Result<u64, Error>;
}

/// The default corpus entry minimising mutational stage
#[derive(Clone, Debug)]
pub struct StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z> {
    /// The mutator(s) this stage uses
    mutator: M,
    /// The factory
    factory: FF,
    /// The runs (=iterations) we are supposed to do
    runs: usize,
    /// The progress helper for this stage, keeping track of resumes after timeouts/crashes
    restart_helper: ExecutionCountRestartHelper,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(CS, E, EM, F1, F2, I, IP, OT, Z)>,
}

impl<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z> UsesState
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z>
where
    CS: Scheduler,
    M: Mutator<I, CS::State>,
    Z: ExecutionProcessor<OT, State = CS::State>,
    CS::State: HasCorpus,
    IP: MutatedTransformPost<CS::State> + Clone,
    I: MutatedTransform<CS::Input, CS::State, Post = IP> + Clone,
{
    type State = CS::State;
}

impl<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z> Stage<E, EM, Z>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z>
where
    CS: Scheduler + RemovableScheduler,
    CS::State: HasCorpus + HasSolutions + HasExecutions + HasMaxSize + HasCorpus + HasMetadata,
    <CS::State as UsesInput>::Input: HasLen + Hash,
    E: Executor<EM, Z> + HasObservers<Observers = OT, State = CS::State>,
    EM: EventFirer<State = CS::State>,
    F1: Feedback<CS::State>,
    F2: Feedback<CS::State>,
    FF: FeedbackFactory<F2, CS::State, OT>,
    M: Mutator<I, CS::State>,
    OT: ObserversTuple<CS::State>,
    Z: ExecutionProcessor<OT, State = CS::State>
        + ExecutesInput<E, EM>
        + HasFeedback<Feedback = F1>
        + HasScheduler<Scheduler = CS>,
    IP: MutatedTransformPost<CS::State> + Clone,
    I: MutatedTransform<CS::Input, CS::State, Post = IP> + Clone,
{
    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        self.restart_helper.restart_progress_should_run(state)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        self.restart_helper.clear_restart_progress(state)
    }

    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut CS::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        self.perform_minification(fuzzer, executor, state, manager)?;

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        Ok(())
    }
}

impl<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z> FeedbackFactory<F2, Z::State, OT>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z>
where
    F2: Feedback<Z::State>,
    FF: FeedbackFactory<F2, Z::State, OT>,
    Z: UsesState,
{
    fn create_feedback(&self, ctx: &OT) -> F2 {
        self.factory.create_feedback(ctx)
    }
}

impl<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z> TMinMutationalStage<CS, E, EM, F1, F2, I, IP, M, OT, Z>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z>
where
    CS: Scheduler + RemovableScheduler,
    E: HasObservers<Observers = OT, State = CS::State> + Executor<EM, Z>,
    EM: EventFirer<State = CS::State>,
    F1: Feedback<CS::State>,
    F2: Feedback<CS::State>,
    FF: FeedbackFactory<F2, CS::State, OT>,
    <CS::State as UsesInput>::Input: HasLen + Hash,
    M: Mutator<I, CS::State>,
    OT: ObserversTuple<CS::State>,
    CS::State: HasCorpus + HasSolutions + HasExecutions + HasMaxSize + HasMetadata,
    Z: ExecutionProcessor<OT, State = CS::State>
        + ExecutesInput<E, EM>
        + HasFeedback<Feedback = F1>
        + HasScheduler<Scheduler = CS>,
    IP: MutatedTransformPost<CS::State> + Clone,
    I: MutatedTransform<CS::Input, CS::State, Post = IP> + Clone,
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
    fn iterations(&self, _state: &mut CS::State) -> Result<usize, Error> {
        Ok(self.runs)
    }

    fn execs_since_progress_start(&mut self, state: &mut <Z>::State) -> Result<u64, Error> {
        self.restart_helper.execs_since_progress_start(state)
    }
}

impl<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z>
    StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, IP, M, OT, Z>
where
    CS: Scheduler,
    M: Mutator<I, CS::State>,
    Z: ExecutionProcessor<OT, State = CS::State>,
    CS::State: HasCorpus,
    IP: MutatedTransformPost<CS::State> + Clone,
    I: MutatedTransform<CS::Input, CS::State, Post = IP> + Clone,
{
    /// Creates a new minimizing mutational stage that will minimize provided corpus entries
    pub fn new(mutator: M, factory: FF, runs: usize) -> Self {
        Self {
            mutator,
            factory,
            runs,
            restart_helper: ExecutionCountRestartHelper::default(),
            phantom: PhantomData,
        }
    }
}

/// A feedback which checks if the hash of the currently observed map is equal to the original hash
/// provided
#[derive(Clone, Debug)]
pub struct MapEqualityFeedback<C, M, S> {
    name: Cow<'static, str>,
    map_ref: Handle<C>,
    orig_hash: u64,
    phantom: PhantomData<(M, S)>,
}

impl<C, M, S> Named for MapEqualityFeedback<C, M, S> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<C, M, S> HasObserverHandle for MapEqualityFeedback<C, M, S> {
    type Observer = C;

    fn observer_handle(&self) -> &Handle<Self::Observer> {
        &self.map_ref
    }
}

impl<C, M, S> Feedback<S> for MapEqualityFeedback<C, M, S>
where
    M: MapObserver,
    C: AsRef<M>,
    S: State,
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
            .get(self.observer_handle())
            .expect("Should have been provided valid observer name.");
        Ok(obs.as_ref().hash_simple() == self.orig_hash)
    }
}

/// A feedback factory for ensuring that the maps for minimized inputs are the same
#[derive(Debug, Clone)]
pub struct MapEqualityFactory<C, M, S> {
    map_ref: Handle<C>,
    phantom: PhantomData<(C, M, S)>,
}

impl<C, M, S> MapEqualityFactory<C, M, S>
where
    M: MapObserver,
    C: AsRef<M> + Handled,
{
    /// Creates a new map equality feedback for the given observer
    pub fn new(obs: &C) -> Self {
        Self {
            map_ref: obs.handle(),
            phantom: PhantomData,
        }
    }
}

impl<C, M, S> HasObserverHandle for MapEqualityFactory<C, M, S> {
    type Observer = C;

    fn observer_handle(&self) -> &Handle<C> {
        &self.map_ref
    }
}

impl<C, M, OT, S> FeedbackFactory<MapEqualityFeedback<C, M, S>, S, OT>
    for MapEqualityFactory<C, M, S>
where
    M: MapObserver,
    C: AsRef<M> + Handled,
    OT: ObserversTuple<S>,
    S: State + Debug,
{
    fn create_feedback(&self, observers: &OT) -> MapEqualityFeedback<C, M, S> {
        let obs = observers
            .get(self.observer_handle())
            .expect("Should have been provided valid observer name.");
        MapEqualityFeedback {
            name: Cow::from("MapEq"),
            map_ref: obs.handle(),
            orig_hash: obs.as_ref().hash_simple(),
            phantom: PhantomData,
        }
    }
}
