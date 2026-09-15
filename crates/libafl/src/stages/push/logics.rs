//! Control flow and logic push stages (If, While, Closure, `IfElse`).

use alloc::borrow::Cow;
use core::fmt::Debug;

use libafl_bolts::{Error, Named, tuples::HasConstLen};

use super::{PushStage, PushStagesTuple, StageStep};
use crate::{
    common::HasNamedMetadata,
    corpus::HasCurrentCorpusId,
    fuzzer::BorrowedObservation,
    stages::{Restartable, RetryCountRestartHelper},
};

/// A push stage that executes a user-provided closure on every step.
/// A stage that executes a user-provided closure on every step.
pub struct ClosureStage<CB, I> {
    name: Cow<'static, str>,
    closure: CB,
    phantom: core::marker::PhantomData<I>,
}

/// Backwards compatibility alias for [`ClosureStage`].
pub type ClosurePushStage<CB, I> = ClosureStage<CB, I>;

impl<CB, I> Debug for ClosureStage<CB, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClosureStage")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<CB, I> ClosureStage<CB, I> {
    /// Create a new closure stage.
    pub fn new(closure: CB) -> Self {
        Self::with_name(closure, "ClosureStage")
    }

    /// Create a new closure stage with a custom name.
    pub fn with_name<N: Into<Cow<'static, str>>>(closure: CB, name: N) -> Self {
        Self {
            name: name.into(),
            closure,
            phantom: core::marker::PhantomData,
        }
    }
}

impl<CB, I> Named for ClosureStage<CB, I> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB, I, S> Restartable<S> for ClosureStage<CB, I>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::no_retry(state, &self.name)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<CB, EM, I, OT, S> PushStage<EM, I, OT, S> for ClosureStage<CB, I>
where
    CB: FnMut(&mut S, &mut EM) -> Result<StageStep<I>, Error>,
{
    fn init(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        Ok(())
    }

    fn step(&mut self, state: &mut S, manager: &mut EM) -> Result<StageStep<I>, Error> {
        (self.closure)(state, manager)
    }

    fn deinit(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        Ok(())
    }
}

/// Metadata storing the conditional evaluation state of an [`IfStage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct IfStageMetadata {
    /// Whether the `if` branch is currently active.
    pub active: bool,
    /// Active inner stage index for `post_exec` routing.
    pub current_stage_idx: Option<usize>,
    /// Saved inner stage ID for resuming `if_stages`.
    pub inner_stage_id: Option<crate::stages::StageId>,
}

libafl_bolts::impl_serdeany!(IfStageMetadata);

/// A stage that conditionally executes an inner tuple of stages if a predicate is true.
#[derive(Debug)]
pub struct IfStage<CB, ST> {
    name: Cow<'static, str>,
    closure: CB,
    if_stages: ST,
}

/// Backwards compatibility alias for [`IfStage`].
pub type IfPushStage<CB, ST> = IfStage<CB, ST>;

impl<CB, ST> IfStage<CB, ST> {
    /// Create a new conditional `IfStage`.
    pub fn new(closure: CB, if_stages: ST) -> Self {
        Self::with_name(closure, if_stages, "IfStage")
    }

    /// Create a new conditional `IfStage` with a custom name.
    pub fn with_name<N: Into<Cow<'static, str>>>(closure: CB, if_stages: ST, name: N) -> Self {
        Self {
            name: name.into(),
            closure,
            if_stages,
        }
    }
}

impl<CB, ST> Named for IfStage<CB, ST> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB, ST, S> Restartable<S> for IfStage<CB, ST>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<CB, EM, I, OT, S, ST> PushStage<EM, I, OT, S> for IfStage<CB, ST>
where
    CB: FnMut(&mut S, &mut EM) -> Result<bool, Error>,
    ST: PushStagesTuple<EM, I, OT, S> + HasConstLen,
    S: HasNamedMetadata + crate::state::HasCurrentStageId,
{
    fn init(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        let saved_stage_id = state.current_stage_id().ok().flatten();
        let active = if let Some(meta) = state
            .named_metadata_map()
            .get::<IfStageMetadata>(&self.name)
        {
            meta.active
        } else {
            let active = (self.closure)(state, manager)?;
            state.add_named_metadata(
                &self.name,
                IfStageMetadata {
                    active,
                    current_stage_idx: None,
                    inner_stage_id: None,
                },
            );
            active
        };
        if active {
            let _ = state.clear_stage_id();
            self.if_stages.init_all(state, manager)?;
            let inner_stage_id = state.current_stage_id().ok().flatten();
            if let Ok(meta) = state.named_metadata_mut::<IfStageMetadata>(&self.name) {
                meta.inner_stage_id = inner_stage_id;
            }
            if let Some(id) = saved_stage_id {
                let _ = state.set_current_stage_id(id);
            } else {
                let _ = state.clear_stage_id();
            }
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, manager: &mut EM) -> Result<StageStep<I>, Error> {
        let (active, inner_stage_id) = state
            .named_metadata_map()
            .get::<IfStageMetadata>(&self.name)
            .map_or((false, None), |m| (m.active, m.inner_stage_id));

        if !active {
            return Ok(StageStep::Done);
        }

        let saved_stage_id = state.current_stage_id().ok().flatten();
        if let Some(id) = inner_stage_id {
            let _ = state.set_current_stage_id(id);
        } else {
            let _ = state.clear_stage_id();
        }

        let step_res = self.if_stages.step_all(state, manager);
        let new_inner_stage_id = state.current_stage_id().ok().flatten();

        if let Some(id) = saved_stage_id {
            let _ = state.set_current_stage_id(id);
        } else {
            let _ = state.clear_stage_id();
        }

        match step_res? {
            StageStep::Execute(mut req) => {
                let stage_idx = req.tag.map(|t| t.stage_idx);
                if let Ok(meta) = state.named_metadata_mut::<IfStageMetadata>(&self.name) {
                    meta.current_stage_idx = stage_idx;
                    meta.inner_stage_id = new_inner_stage_id;
                }
                req.tag = None;
                Ok(StageStep::Execute(req))
            }
            StageStep::Done => {
                self.if_stages.deinit_all(state, manager)?;
                if let Ok(meta) = state.named_metadata_mut::<IfStageMetadata>(&self.name) {
                    meta.active = false;
                    meta.current_stage_idx = None;
                    meta.inner_stage_id = None;
                }
                Ok(StageStep::Done)
            }
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        obs: BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        let (active, current_stage_idx) = state
            .named_metadata_map()
            .get::<IfStageMetadata>(&self.name)
            .map_or((false, None), |m| (m.active, m.current_stage_idx));
        if active && let Some(idx) = current_stage_idx {
            self.if_stages.post_exec_stage(idx, state, manager, obs)?;
        }
        Ok(())
    }

    fn deinit(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        let active = state
            .named_metadata_map()
            .get::<IfStageMetadata>(&self.name)
            .is_some_and(|m| m.active);
        if active {
            self.if_stages.deinit_all(state, manager)?;
        }
        let _ = state
            .named_metadata_map_mut()
            .remove::<IfStageMetadata>(&self.name);
        Ok(())
    }
}

/// Metadata storing the branch selection of an [`IfElseStage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct IfElseStageMetadata {
    /// Selected branch (`Some(true)` = `if`, `Some(false)` = `else`, `None` = inactive).
    pub branch_if: Option<bool>,
    /// Active inner stage index for `post_exec` routing.
    pub current_stage_idx: Option<usize>,
    /// Saved inner stage ID for resuming inner stages.
    pub inner_stage_id: Option<crate::stages::StageId>,
}

libafl_bolts::impl_serdeany!(IfElseStageMetadata);

/// A stage that conditionally executes one of two inner tuples of stages.
#[derive(Debug)]
pub struct IfElseStage<CB, ST1, ST2> {
    name: Cow<'static, str>,
    closure: CB,
    if_stages: ST1,
    else_stages: ST2,
}

/// Backwards compatibility alias for [`IfElseStage`].
pub type IfElsePushStage<CB, ST1, ST2> = IfElseStage<CB, ST1, ST2>;

impl<CB, ST1, ST2> IfElseStage<CB, ST1, ST2> {
    /// Create a new `IfElseStage`.
    pub fn new(closure: CB, if_stages: ST1, else_stages: ST2) -> Self {
        Self::with_name(closure, if_stages, else_stages, "IfElseStage")
    }

    /// Create a new `IfElseStage` with a custom name.
    pub fn with_name<N: Into<Cow<'static, str>>>(
        closure: CB,
        if_stages: ST1,
        else_stages: ST2,
        name: N,
    ) -> Self {
        Self {
            name: name.into(),
            closure,
            if_stages,
            else_stages,
        }
    }
}

impl<CB, ST1, ST2> Named for IfElseStage<CB, ST1, ST2> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB, ST1, ST2, S> Restartable<S> for IfElseStage<CB, ST1, ST2>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<CB, EM, I, OT, S, ST1, ST2> PushStage<EM, I, OT, S> for IfElseStage<CB, ST1, ST2>
where
    CB: FnMut(&mut S, &mut EM) -> Result<bool, Error>,
    ST1: PushStagesTuple<EM, I, OT, S> + HasConstLen,
    ST2: PushStagesTuple<EM, I, OT, S> + HasConstLen,
    S: HasNamedMetadata + crate::state::HasCurrentStageId,
{
    fn init(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        let saved_stage_id = state.current_stage_id().ok().flatten();
        let cond = if let Some(meta) = state
            .named_metadata_map()
            .get::<IfElseStageMetadata>(&self.name)
            && let Some(cond) = meta.branch_if
        {
            cond
        } else {
            let cond = (self.closure)(state, manager)?;
            state.add_named_metadata(
                &self.name,
                IfElseStageMetadata {
                    branch_if: Some(cond),
                    current_stage_idx: None,
                    inner_stage_id: None,
                },
            );
            cond
        };
        let _ = state.clear_stage_id();
        if cond {
            self.if_stages.init_all(state, manager)?;
        } else {
            self.else_stages.init_all(state, manager)?;
        }
        let inner_stage_id = state.current_stage_id().ok().flatten();
        if let Ok(meta) = state.named_metadata_mut::<IfElseStageMetadata>(&self.name) {
            meta.inner_stage_id = inner_stage_id;
        }
        if let Some(id) = saved_stage_id {
            let _ = state.set_current_stage_id(id);
        } else {
            let _ = state.clear_stage_id();
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, manager: &mut EM) -> Result<StageStep<I>, Error> {
        let (branch_if, inner_stage_id) = state
            .named_metadata_map()
            .get::<IfElseStageMetadata>(&self.name)
            .map_or((None, None), |m| (m.branch_if, m.inner_stage_id));

        let saved_stage_id = state.current_stage_id().ok().flatten();
        if let Some(id) = inner_stage_id {
            let _ = state.set_current_stage_id(id);
        } else {
            let _ = state.clear_stage_id();
        }

        let res = match branch_if {
            Some(true) => self.if_stages.step_all(state, manager),
            Some(false) => self.else_stages.step_all(state, manager),
            None => {
                if let Some(id) = saved_stage_id {
                    let _ = state.set_current_stage_id(id);
                } else {
                    let _ = state.clear_stage_id();
                }
                return Ok(StageStep::Done);
            }
        };
        let new_inner_stage_id = state.current_stage_id().ok().flatten();
        if let Some(id) = saved_stage_id {
            let _ = state.set_current_stage_id(id);
        } else {
            let _ = state.clear_stage_id();
        }

        match res? {
            StageStep::Execute(mut req) => {
                let stage_idx = req.tag.map(|t| t.stage_idx);
                if let Ok(meta) = state.named_metadata_mut::<IfElseStageMetadata>(&self.name) {
                    meta.current_stage_idx = stage_idx;
                    meta.inner_stage_id = new_inner_stage_id;
                }
                req.tag = None;
                Ok(StageStep::Execute(req))
            }
            StageStep::Done => {
                if branch_if == Some(true) {
                    self.if_stages.deinit_all(state, manager)?;
                } else if branch_if == Some(false) {
                    self.else_stages.deinit_all(state, manager)?;
                }
                if let Ok(meta) = state.named_metadata_mut::<IfElseStageMetadata>(&self.name) {
                    meta.branch_if = None;
                    meta.current_stage_idx = None;
                    meta.inner_stage_id = None;
                }
                Ok(StageStep::Done)
            }
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        obs: BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        let (branch_if, current_stage_idx) = state
            .named_metadata_map()
            .get::<IfElseStageMetadata>(&self.name)
            .map_or((None, None), |m| (m.branch_if, m.current_stage_idx));
        match (branch_if, current_stage_idx) {
            (Some(true), Some(idx)) => {
                self.if_stages.post_exec_stage(idx, state, manager, obs)?;
            }
            (Some(false), Some(idx)) => {
                self.else_stages.post_exec_stage(idx, state, manager, obs)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn deinit(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        let branch_if = state
            .named_metadata_map()
            .get::<IfElseStageMetadata>(&self.name)
            .and_then(|m| m.branch_if);
        if let Some(cond) = branch_if {
            if cond {
                self.if_stages.deinit_all(state, manager)?;
            } else {
                self.else_stages.deinit_all(state, manager)?;
            }
        }
        let _ = state
            .named_metadata_map_mut()
            .remove::<IfElseStageMetadata>(&self.name);
        Ok(())
    }
}

/// Metadata storing the loop active state of a [`WhileStage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct WhileStageMetadata {
    /// Whether the `while` loop body is currently active.
    pub active: bool,
    /// Active inner stage index for `post_exec` routing.
    pub current_stage_idx: Option<usize>,
    /// Saved inner stage ID for resuming inner stages.
    pub inner_stage_id: Option<crate::stages::StageId>,
}

libafl_bolts::impl_serdeany!(WhileStageMetadata);

/// A stage that loops an inner tuple of stages while a predicate is true.
#[derive(Debug)]
pub struct WhileStage<CB, ST> {
    name: Cow<'static, str>,
    closure: CB,
    stages: ST,
}

/// Backwards compatibility alias for [`WhileStage`].
pub type WhilePushStage<CB, ST> = WhileStage<CB, ST>;

impl<CB, ST> WhileStage<CB, ST> {
    /// Create a new `WhileStage`.
    pub fn new(closure: CB, stages: ST) -> Self {
        Self::with_name(closure, stages, "WhileStage")
    }

    /// Create a new `WhileStage` with a custom name.
    pub fn with_name<N: Into<Cow<'static, str>>>(closure: CB, stages: ST, name: N) -> Self {
        Self {
            name: name.into(),
            closure,
            stages,
        }
    }
}

impl<CB, ST> Named for WhileStage<CB, ST> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB, ST, S> Restartable<S> for WhileStage<CB, ST>
where
    S: HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<CB, EM, I, OT, S, ST> PushStage<EM, I, OT, S> for WhileStage<CB, ST>
where
    CB: FnMut(&mut S, &mut EM) -> Result<bool, Error>,
    ST: PushStagesTuple<EM, I, OT, S> + HasConstLen,
    S: HasNamedMetadata + crate::state::HasCurrentStageId,
{
    fn init(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        let saved_stage_id = state.current_stage_id().ok().flatten();
        let active = if let Some(meta) = state
            .named_metadata_map()
            .get::<WhileStageMetadata>(&self.name)
        {
            meta.active
        } else {
            let active = (self.closure)(state, manager)?;
            state.add_named_metadata(
                &self.name,
                WhileStageMetadata {
                    active,
                    current_stage_idx: None,
                    inner_stage_id: None,
                },
            );
            active
        };
        if active {
            let _ = state.clear_stage_id();
            self.stages.init_all(state, manager)?;
            let inner_stage_id = state.current_stage_id().ok().flatten();
            if let Ok(meta) = state.named_metadata_mut::<WhileStageMetadata>(&self.name) {
                meta.inner_stage_id = inner_stage_id;
            }
            if let Some(id) = saved_stage_id {
                let _ = state.set_current_stage_id(id);
            } else {
                let _ = state.clear_stage_id();
            }
        }
        Ok(())
    }

    fn step(&mut self, state: &mut S, manager: &mut EM) -> Result<StageStep<I>, Error> {
        let (active, inner_stage_id) = state
            .named_metadata_map()
            .get::<WhileStageMetadata>(&self.name)
            .map_or((false, None), |m| (m.active, m.inner_stage_id));

        if !active {
            return Ok(StageStep::Done);
        }

        let saved_stage_id = state.current_stage_id().ok().flatten();
        if let Some(id) = inner_stage_id {
            let _ = state.set_current_stage_id(id);
        } else {
            let _ = state.clear_stage_id();
        }

        let step_res = self.stages.step_all(state, manager);
        let new_inner_stage_id = state.current_stage_id().ok().flatten();

        if let Some(id) = saved_stage_id {
            let _ = state.set_current_stage_id(id);
        } else {
            let _ = state.clear_stage_id();
        }

        match step_res? {
            StageStep::Execute(mut req) => {
                let stage_idx = req.tag.map(|t| t.stage_idx);
                if let Ok(meta) = state.named_metadata_mut::<WhileStageMetadata>(&self.name) {
                    meta.current_stage_idx = stage_idx;
                    meta.inner_stage_id = new_inner_stage_id;
                }
                req.tag = None;
                Ok(StageStep::Execute(req))
            }
            StageStep::Done => {
                self.stages.deinit_all(state, manager)?;
                let next_active = (self.closure)(state, manager)?;
                if let Ok(meta) = state.named_metadata_mut::<WhileStageMetadata>(&self.name) {
                    meta.active = next_active;
                    meta.current_stage_idx = None;
                    meta.inner_stage_id = None;
                }
                if next_active {
                    let _ = state.clear_stage_id();
                    self.stages.init_all(state, manager)?;
                    let step_res = self.stages.step_all(state, manager);
                    let next_inner_stage_id = state.current_stage_id().ok().flatten();
                    if let Some(id) = saved_stage_id {
                        let _ = state.set_current_stage_id(id);
                    } else {
                        let _ = state.clear_stage_id();
                    }
                    match step_res? {
                        StageStep::Execute(mut req) => {
                            let stage_idx = req.tag.map(|t| t.stage_idx);
                            if let Ok(meta) =
                                state.named_metadata_mut::<WhileStageMetadata>(&self.name)
                            {
                                meta.current_stage_idx = stage_idx;
                                meta.inner_stage_id = next_inner_stage_id;
                            }
                            req.tag = None;
                            Ok(StageStep::Execute(req))
                        }
                        StageStep::Done => Ok(StageStep::Done),
                    }
                } else {
                    Ok(StageStep::Done)
                }
            }
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        obs: BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        let (active, current_stage_idx) = state
            .named_metadata_map()
            .get::<WhileStageMetadata>(&self.name)
            .map_or((false, None), |m| (m.active, m.current_stage_idx));
        if active && let Some(idx) = current_stage_idx {
            self.stages.post_exec_stage(idx, state, manager, obs)?;
        }
        Ok(())
    }

    fn deinit(&mut self, state: &mut S, manager: &mut EM) -> Result<(), Error> {
        let active = state
            .named_metadata_map()
            .get::<WhileStageMetadata>(&self.name)
            .is_some_and(|m| m.active);
        if active {
            self.stages.deinit_all(state, manager)?;
        }
        let _ = state
            .named_metadata_map_mut()
            .remove::<WhileStageMetadata>(&self.name);
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
#[allow(
    clippy::type_complexity,
    clippy::match_wildcard_for_single_variants,
    clippy::duration_suboptimal_units
)]
mod tests {
    use alloc::vec;

    use libafl_bolts::{rands::StdRand, tuples::tuple_list};

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        fuzzer::ExecutionRequest,
        inputs::BytesInput,
        observers::StdMapObserver,
        stages::push::CalibrationPushStage,
        state::StdState,
    };

    #[test]
    fn test_closure_push_stage() {
        let called = core::sync::atomic::AtomicBool::new(false);
        let mut stage = ClosurePushStage::<_, BytesInput>::new(
            |_state: &mut StdState<
                InMemoryCorpus<BytesInput>,
                BytesInput,
                StdRand,
                InMemoryCorpus<BytesInput>,
            >,
             _mgr: &mut NopEventManager| {
                called.store(true, core::sync::atomic::Ordering::SeqCst);
                Ok(StageStep::Execute(ExecutionRequest::single(
                    BytesInput::new(vec![1, 2, 3]),
                )))
            },
        );

        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_corpus_id(id).unwrap();
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();
        let res = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(called.load(core::sync::atomic::Ordering::SeqCst));
        assert!(matches!(res, StageStep::Execute(_)));
        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }

    #[test]
    fn test_if_push_stage() {
        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_corpus_id(id).unwrap();
        let mut mgr = NopEventManager::new();

        let inner_stage = CalibrationPushStage::with_runs(1);
        let mut if_stage =
            IfPushStage::new(|_s: &mut _, _m: &mut _| Ok(true), tuple_list!(inner_stage));

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut if_stage, &mut state, &mut mgr).unwrap();
        let res = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut if_stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(res, StageStep::Execute(_)));
        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut if_stage, &mut state, &mut mgr).unwrap();
    }

    #[derive(Debug)]
    struct CountingStage {
        name: Cow<'static, str>,
        stepped: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
        post_exec_count: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
    }

    impl Named for CountingStage {
        fn name(&self) -> &Cow<'static, str> {
            &self.name
        }
    }

    impl<S> Restartable<S> for CountingStage {
        fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
            Ok(true)
        }
        fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
            Ok(())
        }
    }

    impl<EM, I, OT, S> PushStage<EM, I, OT, S> for CountingStage
    where
        I: Default,
    {
        fn init(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), Error> {
            Ok(())
        }

        fn step(&mut self, _state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
            let prev = self
                .stepped
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            if prev == 0 {
                Ok(StageStep::Execute(ExecutionRequest::single(I::default())))
            } else {
                Ok(StageStep::Done)
            }
        }

        fn post_exec(
            &mut self,
            _state: &mut S,
            _manager: &mut EM,
            _obs: BorrowedObservation<'_, I, OT>,
        ) -> Result<(), Error> {
            self.post_exec_count
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn deinit(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn test_if_stage_routes_post_exec_to_active_inner_stage_only() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicUsize, Ordering};
        type TestObservers = (StdMapObserver<'static, u8, false>, ());

        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_corpus_id(id).unwrap();
        let mut mgr = NopEventManager::new();

        let s1_post = Arc::new(AtomicUsize::new(0));
        let s2_post = Arc::new(AtomicUsize::new(0));

        let stage1 = CountingStage {
            name: Cow::Borrowed("stage1"),
            stepped: Arc::new(AtomicUsize::new(0)),
            post_exec_count: s1_post.clone(),
        };
        let stage2 = CountingStage {
            name: Cow::Borrowed("stage2"),
            stepped: Arc::new(AtomicUsize::new(0)),
            post_exec_count: s2_post.clone(),
        };

        let mut if_stage = IfPushStage::new(
            |_s: &mut _, _m: &mut _| Ok(true),
            tuple_list!(stage1, stage2),
        );

        let mut map = [0u8; 16];
        let observers: TestObservers = (
            unsafe { StdMapObserver::from_mut_ptr("map", map.as_mut_ptr(), map.len()) },
            (),
        );
        let input = BytesInput::new(vec![1]);

        PushStage::<NopEventManager, BytesInput, TestObservers, _>::init(
            &mut if_stage,
            &mut state,
            &mut mgr,
        )
        .unwrap();

        // Step 1: stage1 yields Execute
        let step1 = PushStage::<NopEventManager, BytesInput, TestObservers, _>::step(
            &mut if_stage,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        assert!(matches!(step1, StageStep::Execute(_)));

        // post_exec should ONLY route to stage1
        PushStage::<NopEventManager, BytesInput, TestObservers, _>::post_exec(
            &mut if_stage,
            &mut state,
            &mut mgr,
            BorrowedObservation {
                input: &input,
                observers: &observers,
                exit_kind: crate::executors::ExitKind::Ok,
                id: Some(0),
                tag: None,
                exec_time: None,
            },
        )
        .unwrap();
        assert_eq!(s1_post.load(Ordering::SeqCst), 1);
        assert_eq!(s2_post.load(Ordering::SeqCst), 0);

        // Step 2: stage1 returns Done, stage2 yields Execute
        let step2 = PushStage::<NopEventManager, BytesInput, TestObservers, _>::step(
            &mut if_stage,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        assert!(matches!(step2, StageStep::Execute(_)));

        // post_exec should ONLY route to stage2
        PushStage::<NopEventManager, BytesInput, TestObservers, _>::post_exec(
            &mut if_stage,
            &mut state,
            &mut mgr,
            BorrowedObservation {
                input: &input,
                observers: &observers,
                exit_kind: crate::executors::ExitKind::Ok,
                id: Some(1),
                tag: None,
                exec_time: None,
            },
        )
        .unwrap();
        assert_eq!(s1_post.load(Ordering::SeqCst), 1);
        assert_eq!(s2_post.load(Ordering::SeqCst), 1);

        PushStage::<NopEventManager, BytesInput, TestObservers, _>::deinit(
            &mut if_stage,
            &mut state,
            &mut mgr,
        )
        .unwrap();
    }
}
