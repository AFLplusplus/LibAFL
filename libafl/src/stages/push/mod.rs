//! While normal stages call the executor over and over again, push stages turn this concept upside down:
//! A push stage instead returns an iterator that generates a new result for each time it gets called.
//! With the new testcase, you will have to take care about testcase execution, manually.
//! The push stage relies on internal mutability of the supplied `Observers`.
//!

use alloc::rc::Rc;

pub mod mutational;
use core::{cell::RefCell, time::Duration};

pub use mutational::*;

// pub use mutational::StdMutationalPushStage;
use crate::{corpus::CorpusId, events::ProgressReporter, executors::ExitKind, Error};

// The shared state for all [`PushStage`]s
/// Should be stored inside a `[Rc<RefCell<_>>`]
#[derive(Clone, Debug)]
pub struct PushStageSharedState<EM, OT, S, Z> {
    /// The state
    pub state: S,
    /// The fuzzer instance
    pub fuzzer: Z,
    /// The event manager
    pub event_mgr: EM,
    /// The observers
    pub observers: OT,
}

impl<EM, OT, S, Z> PushStageSharedState<EM, OT, S, Z> {
    /// Create a new `PushStageSharedState` that can be used by all [`PushStage`]s
    #[must_use]
    pub fn new(fuzzer: Z, state: S, observers: OT, event_mgr: EM) -> Self {
        Self {
            state,
            fuzzer,
            event_mgr,
            observers,
        }
    }
}

/// Helper class for the [`PushStage`] trait, taking care of borrowing the shared state
#[derive(Debug)]
pub struct PushStageHelper<EM, I, OT, S, Z> {
    /// If this stage has already been initalized.
    /// This gets reset to `false` after one iteration of the stage is done.
    pub initialized: bool,
    /// The shared state, keeping track of the corpus and the fuzzer
    #[allow(clippy::type_complexity)]
    pub shared_state: Rc<RefCell<Option<PushStageSharedState<EM, OT, S, Z>>>>,
    /// If the last iteration failed
    pub errored: bool,

    /// The corpus index we're currently working on
    pub current_corpus_id: Option<CorpusId>,

    /// The input we just ran
    pub current_input: Option<I>, // Todo: Get rid of copy

    exit_kind: Rc<RefCell<Option<ExitKind>>>,
}

impl<EM, I, OT, S, Z> PushStageHelper<EM, I, OT, S, Z> {
    /// Create a new [`PushStageHelper`]
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn new(
        shared_state: Rc<RefCell<Option<PushStageSharedState<EM, OT, S, Z>>>>,
        exit_kind_ref: Rc<RefCell<Option<ExitKind>>>,
    ) -> Self {
        Self {
            shared_state,
            initialized: false,
            exit_kind: exit_kind_ref,
            errored: false,
            current_input: None,
            current_corpus_id: None,
        }
    }

    /// Sets the shared state for this helper (and all other helpers owning the same [`RefCell`])
    #[inline]
    pub fn set_shared_state(&mut self, shared_state: PushStageSharedState<EM, OT, S, Z>) {
        (*self.shared_state.borrow_mut()).replace(shared_state);
    }

    /// Takes the shared state from this helper, replacing it with `None`
    #[inline]
    #[allow(clippy::type_complexity)]
    pub fn take_shared_state(&mut self) -> Option<PushStageSharedState<EM, OT, S, Z>> {
        let shared_state_ref = &mut (*self.shared_state).borrow_mut();
        shared_state_ref.take()
    }

    /// Takes the exit kind of the last run
    #[inline]
    #[must_use]
    pub fn take_exit_kind(&self) -> Option<ExitKind> {
        self.exit_kind.take()
    }

    /// Resets the exit kind
    #[inline]
    pub fn reset_exit_kind(&mut self) {
        self.exit_kind.replace(None);
    }

    /// Resets this state after a full stage iter.
    fn end_of_iter(&mut self, shared_state: PushStageSharedState<EM, OT, S, Z>, errored: bool) {
        self.set_shared_state(shared_state);
        self.errored = errored;
        self.current_corpus_id = None;
        if errored {
            self.initialized = false;
        }
    }
}

/// A push stage is a generator that returns a single testcase for each call.
/// It's an iterator so we can chain it.
/// After it has finished once, we will call it agan for the next fuzzer round.
pub trait PushStage<EM, OT, S, Z> {
    /// The input for this stage. This is not necessarily the same as the type stored in the corpus.
    type Input;

    /// Gets the [`PushStageHelper`]
    fn push_stage_helper(&self) -> &PushStageHelper<EM, Self::Input, OT, S, Z>;
    /// Gets the [`PushStageHelper`] (mutable)
    fn push_stage_helper_mut(&mut self) -> &mut PushStageHelper<EM, Self::Input, OT, S, Z>;

    /// Set the current corpus index this stage works on
    fn set_current_corpus_id(&mut self, corpus_id: CorpusId) {
        self.push_stage_helper_mut().current_corpus_id = Some(corpus_id);
    }

    /// Called by `next_std` when this stage is being initialized.
    /// This is called before the first iteration of the stage.
    /// After the stage has finished once (after `deinit`), this will be called again.
    #[inline]
    fn init(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called before the a test case is executed.
    /// Should return the test case to be executed.
    /// After this stage has finished, or if the stage does not process any inputs, this should return `None`.
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Option<Result<Self::Input, Error>>;

    /// Called after the execution of a testcase finished.
    #[inline]
    fn post_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        _observers: &mut OT,
        _input: Self::Input,
        _exit_kind: ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Called after the stage finished (`pre_exec` returned `None`)
    #[inline]
    fn deinit(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        _observers: &mut OT,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// Blanket implementation for getting the next input from the state
pub trait PushStageNext<EM, OT, S, Z>: PushStage<EM, OT, S, Z> {
    /// This is the default implementation for `next` for this stage
    fn next_std(&mut self) -> Option<Result<Self::Input, Error>>;
}

/// Send a monitor update all 15 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

impl<PS, EM, OT, S, Z> PushStageNext<EM, OT, S, Z> for PS
where
    PS: PushStage<EM, OT, S, Z>,
    EM: ProgressReporter<S>,
{
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
                self.push_stage_helper().take_exit_kind().unwrap(),
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

            if let Err(err) = shared_state
                .event_mgr
                .maybe_report_progress(&mut shared_state.state, STATS_TIMEOUT_DEFAULT)
            {
                self.push_stage_helper_mut().end_of_iter(shared_state, true);
                return Some(Err(err));
            };
        } else {
            self.push_stage_helper_mut().reset_exit_kind();
        }
        self.push_stage_helper_mut()
            .end_of_iter(shared_state, false);
        ret
    }
}
