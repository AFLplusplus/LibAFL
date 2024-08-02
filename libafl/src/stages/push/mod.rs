//! While normal stages call the executor over and over again, push stages turn this concept upside down:
//! A push stage instead returns an iterator that generates a new result for each time it gets called.
//! With the new testcase, you will have to take care about testcase execution, manually.
//! The push stage relies on internal mutability of the supplied `Observers`.
//!

use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

pub mod mutational;
pub use mutational::*;

// pub use mutational::StdMutationalPushStage;
use crate::{corpus::CorpusId, executors::ExitKind, Error};

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

    exit_kind: Rc<Cell<Option<ExitKind>>>,
}

impl<EM, I, OT, S, Z> PushStageHelper<EM, I, OT, S, Z> {
    /// Create a new [`PushStageHelper`]
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn new(
        shared_state: Rc<RefCell<Option<PushStageSharedState<EM, OT, S, Z>>>>,
        exit_kind_ref: Rc<Cell<Option<ExitKind>>>,
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
