/*!
A [`Stage`] is a technique used during fuzzing, working on one [`crate::corpus::Corpus`] entry, and potentially altering it or creating new entries.
A well-known [`Stage`], for example, is the mutational stage, running multiple [`crate::mutators::Mutator`]s against a [`crate::corpus::Testcase`], potentially storing new ones, according to [`crate::feedbacks::Feedback`].
Other stages may enrich [`crate::corpus::Testcase`]s with metadata.
*/

/// Mutational stage is the normal fuzzing stage,
pub mod mutational;
pub use mutational::{MutationalStage, StdMutationalStage};

pub mod push;

pub mod tracing;
pub use tracing::{ShadowTracingStage, TracingStage};

pub mod calibrate;
pub use calibrate::{CalibrationStage, PowerScheduleMetadata};

pub mod power;
pub use power::PowerMutationalStage;

#[cfg(feature = "std")]
pub mod concolic;
#[cfg(feature = "std")]
pub use concolic::ConcolicTracingStage;
#[cfg(feature = "std")]
pub use concolic::SimpleConcolicMutationalStage;

#[cfg(feature = "std")]
pub mod sync;
#[cfg(feature = "std")]
pub use sync::*;

use crate::events::EventFirer;
use crate::events::EventRestarter;
use crate::events::HasEventManagerId;
use crate::events::ProgressReporter;
use crate::state::HasExecutions;
use crate::{
    bolts::rands::Rand,
    corpus::Corpus,
    corpus::CorpusScheduler,
    executors::Executor,
    executors::HasObservers,
    inputs::Input,
    observers::ObserversTuple,
    state::HasRand,
    state::{HasClientPerfMonitor, HasCorpus},
    Error, EvaluatorObservers, ExecutesInput, ExecutionProcessor, HasCorpusScheduler,
};
use core::{convert::From, marker::PhantomData};

use self::push::PushStage;

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, S, Z> {
    /// Run the stage
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

/// A tuple holding all `Stages` used for fuzzing.
pub trait StagesTuple<E, EM, S, Z> {
    /// Performs all `Stages` in this tuple
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for () {
    fn perform_all(
        &mut self,
        _: &mut Z,
        _: &mut E,
        _: &mut S,
        _: &mut EM,
        _: usize,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, E, EM, S, Z> StagesTuple<E, EM, S, Z> for (Head, Tail)
where
    Head: Stage<E, EM, S, Z>,
    Tail: StagesTuple<E, EM, S, Z>,
{
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        // Perform the current stage
        self.0
            .perform(fuzzer, executor, state, manager, corpus_idx)?;

        // Execute the remaining stages
        self.1
            .perform_all(fuzzer, executor, state, manager, corpus_idx)
    }
}

pub struct ClosureStage<CB, E, EM, S, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM, usize) -> Result<(), Error>,
{
    closure: CB,
    phantom: PhantomData<(E, EM, S, Z)>,
}

impl<CB, E, EM, S, Z> Stage<E, EM, S, Z> for ClosureStage<CB, E, EM, S, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM, usize) -> Result<(), Error>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        (self.closure)(fuzzer, executor, state, manager, corpus_idx)
    }
}

impl<CB, E, EM, S, Z> ClosureStage<CB, E, EM, S, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM, usize) -> Result<(), Error>,
{
    #[must_use]
    pub fn new(closure: CB) -> Self {
        Self {
            closure,
            phantom: PhantomData,
        }
    }
}

impl<CB, E, EM, S, Z> From<CB> for ClosureStage<CB, E, EM, S, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM, usize) -> Result<(), Error>,
{
    #[must_use]
    fn from(closure: CB) -> Self {
        Self::new(closure)
    }
}

/// Allows us to use a [`push::PushStage`] as a normal [`Stage`]set_corpus_idx
#[allow(clippy::type_complexity)]
pub struct PushStageAdapter<C, CS, EM, I, OT, PS, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId + ProgressReporter<I>,
    I: Input,
    OT: ObserversTuple<I, S>,
    PS: PushStage<C, CS, EM, I, OT, R, S, Z>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R> + HasExecutions,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasCorpusScheduler<CS, I, S>,
{
    push_stage: PS,
    phantom: PhantomData<(C, CS, EM, I, OT, R, S, Z)>,
}

impl<C, CS, EM, I, OT, PS, R, S, Z> PushStageAdapter<C, CS, EM, I, OT, PS, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId + ProgressReporter<I>,
    I: Input,
    OT: ObserversTuple<I, S>,
    PS: PushStage<C, CS, EM, I, OT, R, S, Z>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R> + HasExecutions,
    Z: ExecutionProcessor<I, OT, S> + EvaluatorObservers<I, OT, S> + HasCorpusScheduler<CS, I, S>,
{
    /// Create a new [`PushStageAdapter`], warpping the given [`PushStage`]
    /// to be used as a normal [`Stage`]
    #[must_use]
    pub fn new(push_stage: PS) -> Self {
        Self {
            push_stage,
            phantom: PhantomData,
        }
    }
}

impl<C, CS, E, EM, I, OT, PS, R, S, Z> Stage<E, EM, S, Z>
    for PushStageAdapter<C, CS, EM, I, OT, PS, R, S, Z>
where
    C: Corpus<I>,
    CS: CorpusScheduler<I, S>,
    E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
    EM: EventFirer<I> + EventRestarter<S> + HasEventManagerId + ProgressReporter<I>,
    I: Input,
    OT: ObserversTuple<I, S>,
    PS: PushStage<C, CS, EM, I, OT, R, S, Z>,
    R: Rand,
    S: HasClientPerfMonitor + HasCorpus<C, I> + HasRand<R> + HasExecutions,
    Z: ExecutesInput<I, OT, S, Z>
        + ExecutionProcessor<I, OT, S>
        + EvaluatorObservers<I, OT, S>
        + HasCorpusScheduler<CS, I, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        event_mgr: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let push_stage = &mut self.push_stage;

        push_stage.set_current_corpus_idx(corpus_idx);

        push_stage.init(fuzzer, state, event_mgr, executor.observers_mut())?;

        loop {
            let input =
                match push_stage.pre_exec(fuzzer, state, event_mgr, executor.observers_mut()) {
                    Some(Ok(next_input)) => next_input,
                    Some(Err(err)) => return Err(err),
                    None => break,
                };

            let exit_kind = fuzzer.execute_input(state, executor, event_mgr, &input)?;

            push_stage.post_exec(
                fuzzer,
                state,
                event_mgr,
                executor.observers_mut(),
                input,
                exit_kind,
            )?;
        }

        self.push_stage
            .deinit(fuzzer, state, event_mgr, executor.observers_mut())
    }
}
