//! While normal stages call the executor over and over again, push stages turn this concept upside down:
//! A push stage instead returns an iterator that generates a new result for each time it gets called.
//! With the new testcase, you will have to take care about testcase execution, manually.
//! The push stage relies on internal muttability of the supplied `Observers`.
//!

/// Mutational stage is the normal fuzzing stage.
pub mod mutational;
use alloc::rc::Rc;
use core::{
    cell::{Cell, RefCell},
    time::Duration,
};

pub use mutational::StdMutationalPushStage;

use crate::{
    bolts::current_time,
    events::{EventFirer, EventRestarter, HasEventManagerId, ProgressReporter},
    executors::ExitKind,
    inputs::Input,
    observers::ObserversTuple,
    schedulers::Scheduler,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasRand},
    Error, EvaluatorObservers, ExecutionProcessor, HasScheduler,
};

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);


// The shared state for all [`PushStage`]s
/// Should be stored inside a `[Rc<RefCell<_>>`]
pub trait PushStageSharedState {
    type Scheduler: Scheduler;
    type EventManager: EventFirer + EventRestarter + HasEventManagerId;
    type Input: Input;
    type Observers: ObserversTuple;
    type State: HasClientPerfMonitor + HasCorpus + HasRand;
    type Fuzzer: ExecutionProcessor + EvaluatorObservers + HasScheduler;
}

// The shared state for all [`PushStage`]s
/// Should be stored inside a `[Rc<RefCell<_>>`]
#[derive(Clone, Debug)]
pub struct StdPushStageSharedState
{
    /// The [`crate::state::State`]
    pub state: <Self as PushStageSharedState>::State,
    /// The [`crate::fuzzer::Fuzzer`] instance
    pub fuzzer: <Self as PushStageSharedState>::Fuzzer,
    /// The [`crate::events::EventManager`]
    pub event_mgr: <Self as PushStageSharedState>::EventManager,
    /// The [`crate::observers::ObserversTuple`]
    pub observers: <Self as PushStageSharedState>::Observers,
}

impl<CS, EM, I, OT, S, Z> PushStageSharedState for StdPushStageSharedState
where
    CS: Scheduler,
    EM: EventFirer + EventRestarter + HasEventManagerId,
    I: Input,
    OT: ObserversTuple,
    S: HasClientPerfMonitor + HasCorpus + HasRand,
    Z: ExecutionProcessor + EvaluatorObservers + HasScheduler,
{
    type Scheduler = CS;
    type EventManager = EM;
    type Input = I;
    type Observers = OT;
    type State = S;
    type Fuzzer = Z;
}

impl StdPushStageSharedState
{
    /// Create a new `PushStageSharedState` that can be used by all [`PushStage`]s
    #[must_use]
    pub fn new(fuzzer: <Self as PushStageSharedState>::Fuzzer, state: <Self as PushStageSharedState>::State, observers: <Self as PushStageSharedState>::Observers, event_mgr: <Self as PushStageSharedState>::EventManager) -> Self {
        Self {
            state,
            fuzzer,
            event_mgr,
            observers,
        }
    }
}

/// The PushStageState
trait PushStageHelper {
    type Scheduler: Scheduler;
    type EventManager: EventFirer + EventRestarter + HasEventManagerId;
    type Input: Input;
    type Observers: ObserversTuple;
    type State: HasClientPerfMonitor + HasCorpus + HasRand;
    type Fuzzer: ExecutionProcessor + EvaluatorObservers + HasScheduler;
    type PushStageSharedState: PushStageSharedState<Scheduler = Self::Scheduler, EventManager = Self::EventManager, Input = Self::Input, Observers = Self::Observers, State = Self::State, Fuzzer = Self::Fuzzer>;

}

/// Helper class for the [`PushStage`] trait, taking care of borrowing the shared state
#[derive(Clone, Debug)]
pub struct StdPushStageHelper
{
    /// If this stage has already been initalized.
    /// This gets reset to `false` after one iteration of the stage is done.
    pub initialized: bool,
    /// The last time the monitor was updated
    pub last_monitor_time: Duration,
    /// The shared state, keeping track of the corpus and the fuzzer
    #[allow(clippy::type_complexity)]
    pub shared_state: Rc<RefCell<Option<<Self as PushStageHelper>::PushStageSharedState>>>,
    /// If the last iteration failed
    pub errored: bool,

    /// The corpus index we're currently working on
    pub current_corpus_idx: Option<usize>,

    /// The input we just ran
    pub current_input: Option<<Self as PushStageSharedState>::Input>, // Todo: Get rid of copy

    exit_kind: Rc<Cell<Option<ExitKind>>>,
}

impl<CS, EM, I, OT, S, Z> PushStageHelper for StdPushStageHelper
where
    CS: Scheduler,
    EM: EventFirer + EventRestarter + HasEventManagerId,
    I: Input,
    OT: ObserversTuple,
    S: HasClientPerfMonitor + HasCorpus + HasRand,
    Z: ExecutionProcessor + EvaluatorObservers + HasScheduler,
{
    /// The `Scheduler`
    type Scheduler = S;

    /// The `EventManager`
    type EventManager = EM;

    /// The `Input`
    type Input = I;

    /// The [`ObserversTuple`]
    type Observers = OT;

    /// The `State`
    type State = S;

    /// The `Fuzzer`
    type Fuzzer = Z;
}

impl StdPushStageHelper
{
    /// Create a new [`PushStageHelper`]
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn new(
        shared_state: Rc<RefCell<Option<<Self as PushStageHelper>::PushStageSharedState>>>,
        exit_kind_ref: Rc<Cell<Option<ExitKind>>>,
    ) -> Self {
        Self {
            shared_state,
            initialized: false,
            last_monitor_time: current_time(),
            exit_kind: exit_kind_ref,
            errored: false,
            current_input: None,
            current_corpus_idx: None,
        }
    }

    /// Sets the shared state for this helper (and all other helpers owning the same [`RefCell`])
    #[inline]
    pub fn set_shared_state(&mut self, shared_state: <Self as PushStageHelper>::PushStageSharedState) {
        (*self.shared_state.borrow_mut()).replace(shared_state);
    }

    /// Takes the shared state from this helper, replacing it with `None`
    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn take_shared_state(&mut self) -> Option<<Self as PushStageHelper>::PushStageSharedState> {
        let shared_state_ref = &mut (*self.shared_state).borrow_mut();
        shared_state_ref.take()
    }

    /// Returns the exit kind of the last run
    #[inline]
    #[must_use]
    pub fn exit_kind(&self) -> Option<ExitKind> {
        self.exit_kind.get()
    }

    /// Resets the exit kind
    #[inline]
    pub fn reset_exit_kind(&mut self) {
        self.exit_kind.set(None);
    }

    /// Resets this state after a full stage iter.
    fn end_of_iter(
        &mut self,
        shared_state: <Self as PushStageHelper>::PushStageSharedState,
        errored: bool,
    ) {
        self.set_shared_state(shared_state);
        self.errored = errored;
        self.current_corpus_idx = None;
        if errored {
            self.initialized = false;
        }
    }
}

/// A push stage is a generator that returns a single testcase for each call.
/// It's an iterator so we can chain it.
/// After it has finished once, we will call it agan for the next fuzzer round.
pub trait PushStage: Iterator {
    type Scheduler: Scheduler;
    type EventManager: EventFirer + EventRestarter + HasEventManagerId + ProgressReporter;
    type Input: Input;
    type Observers: ObserversTuple;
    type Stage: HasClientPerfMonitor + HasCorpus + HasRand + HasExecutions;
    type Fuzzer: ExecutionProcessor + EvaluatorObservers + HasScheduler;
    type State;
    type PushStageHelper: PushStageHelper<Scheduler = Self::Scheduler, EventManager = Self::EventManager, Input = Self::Input, Observers = Self::Observers, Fuzzer= Self::Fuzzer, State = Self::State>;

    /// Gets the [`PushStageHelper`]
    fn push_stage_helper(
        &self,
    ) -> &Self::PushStageHelper;

    /// Gets the [`PushStageHelper`] (mutable)
    fn push_stage_helper_mut(
        &mut self,
    ) -> &mut Self::PushStageHelper;

    /// Set the current corpus index this stage works on
    fn set_current_corpus_idx(&mut self, corpus_idx: usize) {
        self.push_stage_helper_mut().current_corpus_idx = Some(corpus_idx);
    }

    /// Called by `next_std` when this stage is being initialized.
    /// This is called before the first iteration of the stage.
    /// After the stage has finished once (after `deinit`), this will be called again.
    #[inline]
    fn init(
        &mut self,
        _fuzzer: &mut Self::Fuzzer,
        _state: &mut Self::Stage,
        _event_mgr: &mut Self::EventManager,
        _observers: &mut Self::Observers,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called before the a test case is executed.
    /// Should return the test case to be executed.
    /// After this stage has finished, or if the stage does not process any inputs, this should return `None`.
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Self::Fuzzer,
        _state: &mut Self::State,
        _event_mgr: &mut Self::EventManager,
        _observers: &mut Self::Observers,
    ) -> Option<Result<Self::Input, Error>>;

    /// Called after the execution of a testcase finished.
    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Self::Fuzzer,
        _state: &mut Self::State,
        _event_mgr: &mut Self::EventManager,
        _observers: &mut Self::Observers,
        _input: Self::Input,
        _exit_kind: ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called after the stage finished (`pre_exec` returned `None`)
    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Self::Fuzzer,
        _state: &mut Self::State,
        _event_mgr: &mut Self::EventManager,
        _observers: &mut Self::Observers,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// This is the default implementation for `next` for this stage
    fn next_std(&mut self) -> Option<Result<Self::Input, Error>> {
        let mut shared_state = {
            let shared_state_ref = &mut (*self.push_stage_helper_mut().shared_state).borrow_mut();
            shared_state_ref.take().unwrap()
        };

        let step_success = if self.push_stage_helper().initialized {
            // We already ran once

            let last_input = self.push_stage_helper_mut().current_input.take().unwrap();

            self.post_exec(
                &mut shared_state.fuzzer,
                &mut shared_state.state,
                &mut shared_state.event_mgr,
                &mut shared_state.observers,
                last_input,
                self.push_stage_helper().exit_kind().unwrap(),
            )
        } else {
            self.init(
                &mut shared_state.fuzzer,
                &mut shared_state.state,
                &mut shared_state.event_mgr,
                &mut shared_state.observers,
            )
        };
        if let Err(err) = step_success {
            self.push_stage_helper_mut().end_of_iter(shared_state, true);
            return Some(Err(err));
        }

        //for i in 0..num {
        let ret = self.pre_exec(
            &mut shared_state.fuzzer,
            &mut shared_state.state,
            &mut shared_state.event_mgr,
            &mut shared_state.observers,
        );
        if ret.is_none() {
            // We're done.
            drop(self.push_stage_helper_mut().current_input.take());
            self.push_stage_helper_mut().initialized = false;

            if let Err(err) = self.deinit(
                &mut shared_state.fuzzer,
                &mut shared_state.state,
                &mut shared_state.event_mgr,
                &mut shared_state.observers,
            ) {
                self.push_stage_helper_mut().end_of_iter(shared_state, true);
                return Some(Err(err));
            };

            let last_monitor_time = self.push_stage_helper().last_monitor_time;

            let new_monitor_time = match shared_state.event_mgr.maybe_report_progress(
                &mut shared_state.state,
                last_monitor_time,
                STATS_TIMEOUT_DEFAULT,
            ) {
                Ok(new_time) => new_time,
                Err(err) => {
                    self.push_stage_helper_mut().end_of_iter(shared_state, true);
                    return Some(Err(err));
                }
            };

            self.push_stage_helper_mut().last_monitor_time = new_monitor_time;
            //self.fuzzer.maybe_report_monitor();
        } else {
            self.push_stage_helper_mut().reset_exit_kind();
        }
        self.push_stage_helper_mut()
            .end_of_iter(shared_state, false);
        ret
    }
}
