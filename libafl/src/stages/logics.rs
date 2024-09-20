//! Stage wrappers that add logics to stage list

use crate::{
    stages::{HasNestedStageStatus, Stage, StageId, StagesTuple},
    Error,
};

/// Progress for nested stages. This merely enters/exits the inner stage's scope.
#[derive(Debug)]
pub struct NestedStageRetryCountRestartHelper;

impl NestedStageRetryCountRestartHelper {
    fn should_restart<S, ST>(state: &mut S, _stage: &ST) -> Result<bool, Error>
    where
        S: HasNestedStageStatus,
    {
        state.enter_inner_stage()?;
        Ok(true)
    }

    fn clear_progress<S, ST>(state: &mut S, _stage: &ST) -> Result<(), Error>
    where
        S: HasNestedStageStatus,
    {
        state.exit_inner_stage()?;
        Ok(())
    }
}

#[derive(Debug)]
/// Perform the stage while the closure evaluates to true
pub struct WhileStage<CB, ST> {
    closure: CB,
    stages: ST,
}

impl<CB, E, EM, S, ST, Z> Stage<E, EM, S, Z> for WhileStage<CB, ST>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM) -> Result<bool, Error>,
    ST: StagesTuple<E, EM, S, Z>,
    S: HasNestedStageStatus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        while state.current_stage_idx()?.is_some()
            || (self.closure)(fuzzer, executor, state, manager)?
        {
            self.stages.perform_all(fuzzer, executor, state, manager)?;
        }

        Ok(())
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        NestedStageRetryCountRestartHelper::should_restart(state, self)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        NestedStageRetryCountRestartHelper::clear_progress(state, self)
    }
}

impl<CB, ST> WhileStage<CB, ST> {
    /// Constructor
    pub fn new<E, EM, S, Z>(closure: CB, stages: ST) -> Self
    where
        CB: FnMut(&mut Z, &mut E, &mut S, &mut EM) -> Result<bool, Error>,
    {
        Self { closure, stages }
    }
}

/// A conditionally enabled stage.
/// If the closure returns true, the wrapped stage will be executed, else it will be skipped.
#[derive(Debug)]
pub struct IfStage<CB, ST> {
    closure: CB,
    if_stages: ST,
}

impl<CB, E, EM, S, ST, Z> Stage<E, EM, S, Z> for IfStage<CB, ST>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM) -> Result<bool, Error>,
    ST: StagesTuple<E, EM, S, Z>,
    S: HasNestedStageStatus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if state.current_stage_idx()?.is_some() || (self.closure)(fuzzer, executor, state, manager)?
        {
            self.if_stages
                .perform_all(fuzzer, executor, state, manager)?;
        }
        Ok(())
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        NestedStageRetryCountRestartHelper::should_restart(state, self)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        NestedStageRetryCountRestartHelper::clear_progress(state, self)
    }
}

impl<CB, ST> IfStage<CB, ST> {
    /// Constructor for this conditionally enabled stage.
    /// If the closure returns true, the wrapped stage will be executed, else it will be skipped.
    pub fn new<E, EM, S, Z>(closure: CB, if_stages: ST) -> Self
    where
        CB: FnMut(&mut Z, &mut E, &mut S, &mut EM) -> Result<bool, Error>,
    {
        Self { closure, if_stages }
    }
}

/// Perform the stage if closure evaluates to true
#[derive(Debug)]
pub struct IfElseStage<CB, ST1, ST2> {
    closure: CB,
    if_stages: ST1,
    else_stages: ST2,
}

impl<CB, E, EM, S, ST1, ST2, Z> Stage<E, EM, S, Z> for IfElseStage<CB, ST1, ST2>
where
    CB: FnMut(&mut Z, &mut E, &mut S, &mut EM) -> Result<bool, Error>,
    ST1: StagesTuple<E, EM, S, Z>,
    ST2: StagesTuple<E, EM, S, Z>,
    S: HasNestedStageStatus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let current = state.current_stage_idx()?;

        let fresh = current.is_none();
        let closure_return = fresh && (self.closure)(fuzzer, executor, state, manager)?;

        if current == Some(StageId(0)) || closure_return {
            if fresh {
                state.set_current_stage_idx(StageId(0))?;
            }
            state.enter_inner_stage()?;
            self.if_stages
                .perform_all(fuzzer, executor, state, manager)?;
        } else {
            if fresh {
                state.set_current_stage_idx(StageId(1))?;
            }
            state.enter_inner_stage()?;
            self.else_stages
                .perform_all(fuzzer, executor, state, manager)?;
        }

        state.exit_inner_stage()?;
        state.clear_stage()?;

        Ok(())
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        NestedStageRetryCountRestartHelper::should_restart(state, self)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        NestedStageRetryCountRestartHelper::clear_progress(state, self)
    }
}

impl<CB, ST1, ST2> IfElseStage<CB, ST1, ST2> {
    /// Constructor
    pub fn new<E, EM, S, Z>(closure: CB, if_stages: ST1, else_stages: ST2) -> Self
    where
        CB: FnMut(&mut Z, &mut E, &mut S, &mut EM) -> Result<bool, Error>,
    {
        Self {
            closure,
            if_stages,
            else_stages,
        }
    }
}

/// A stage wrapper where the stages do not need to be initialized, but can be [`None`].
#[derive(Debug)]
pub struct OptionalStage<ST> {
    stages: Option<ST>,
}

impl<E, EM, ST, S, Z> Stage<E, EM, S, Z> for OptionalStage<ST>
where
    ST: StagesTuple<E, EM, S, Z>,
    S: HasNestedStageStatus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if let Some(stages) = &mut self.stages {
            stages.perform_all(fuzzer, executor, state, manager)
        } else {
            Ok(())
        }
    }

    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        NestedStageRetryCountRestartHelper::should_restart(state, self)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        NestedStageRetryCountRestartHelper::clear_progress(state, self)
    }
}

impl<ST> OptionalStage<ST> {
    /// Constructor for this conditionally enabled stage.
    #[must_use]
    pub fn new(stages: Option<ST>) -> Self {
        Self { stages }
    }

    /// Constructor for this conditionally enabled stage with set stages.
    #[must_use]
    pub fn some(stages: ST) -> Self {
        Self {
            stages: Some(stages),
        }
    }

    /// Constructor for this conditionally enabled stage, without stages set.
    #[must_use]
    pub fn none() -> Self {
        Self { stages: None }
    }
}
