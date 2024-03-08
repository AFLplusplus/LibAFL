//! Stage wrappers that add logics to stage list

use core::marker::PhantomData;

use crate::{
    stages::{HasCurrentStage, HasNestedStageStatus, Stage, StagesTuple},
    state::UsesState,
    Error,
};

/// Progress for nested stages. This merely enters/exits the inner stage's scope.
#[derive(Debug)]
pub struct NestedStageRestartHelper;

impl NestedStageRestartHelper {
    fn restart_progress_should_run<S, ST>(state: &mut S, _stage: &ST) -> Result<bool, Error>
    where
        S: HasNestedStageStatus,
    {
        state.enter_inner_stage()?;
        Ok(true)
    }

    fn clear_restart_progress<S, ST>(state: &mut S, _stage: &ST) -> Result<(), Error>
    where
        S: HasNestedStageStatus,
    {
        state.exit_inner_stage()?;
        Ok(())
    }
}

#[derive(Debug)]
/// Perform the stage while the closure evaluates to true
pub struct WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    closure: CB,
    stages: ST,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, ST, Z> UsesState for WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST, Z> Stage<E, EM, Z> for WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
    E::State: HasNestedStageStatus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        while state.current_stage()?.is_some() || (self.closure)(fuzzer, executor, state, manager)?
        {
            self.stages.perform_all(fuzzer, executor, state, manager)?;
        }

        Ok(())
    }

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        NestedStageRestartHelper::restart_progress_should_run(state, self)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        NestedStageRestartHelper::clear_restart_progress(state, self)
    }
}

impl<CB, E, EM, ST, Z> WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor
    pub fn new(closure: CB, stages: ST) -> Self {
        Self {
            closure,
            stages,
            phantom: PhantomData,
        }
    }
}

/// A conditionally enabled stage.
/// If the closure returns true, the wrapped stage will be executed, else it will be skipped.
#[derive(Debug)]
pub struct IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    closure: CB,
    if_stages: ST,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, ST, Z> UsesState for IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST, Z> Stage<E, EM, Z> for IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
    E::State: HasNestedStageStatus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if state.current_stage()?.is_some() || (self.closure)(fuzzer, executor, state, manager)? {
            self.if_stages
                .perform_all(fuzzer, executor, state, manager)?;
        }
        Ok(())
    }

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        NestedStageRestartHelper::restart_progress_should_run(state, self)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        NestedStageRestartHelper::clear_restart_progress(state, self)
    }
}

impl<CB, E, EM, ST, Z> IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor for this conditionally enabled stage.
    /// If the closure returns true, the wrapped stage will be executed, else it will be skipped.
    pub fn new(closure: CB, if_stages: ST) -> Self {
        Self {
            closure,
            if_stages,
            phantom: PhantomData,
        }
    }
}

/// Perform the stage if closure evaluates to true
#[derive(Debug)]
pub struct IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    closure: CB,
    if_stages: ST1,
    else_stages: ST2,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, ST1, ST2, Z> UsesState for IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST1, ST2, Z> Stage<E, EM, Z> for IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
    E::State: HasNestedStageStatus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let current = state.current_stage()?;

        let fresh = current.is_none();
        let closure_return = fresh && (self.closure)(fuzzer, executor, state, manager)?;

        if current == Some(0) || closure_return {
            if fresh {
                state.set_stage(0)?;
            }
            state.enter_inner_stage()?;
            self.if_stages
                .perform_all(fuzzer, executor, state, manager)?;
        } else {
            if fresh {
                state.set_stage(1)?;
            }
            state.enter_inner_stage()?;
            self.else_stages
                .perform_all(fuzzer, executor, state, manager)?;
        }

        state.exit_inner_stage()?;
        state.clear_stage()?;

        Ok(())
    }

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        NestedStageRestartHelper::restart_progress_should_run(state, self)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        NestedStageRestartHelper::clear_restart_progress(state, self)
    }
}

impl<CB, E, EM, ST1, ST2, Z> IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor
    pub fn new(closure: CB, if_stages: ST1, else_stages: ST2) -> Self {
        Self {
            closure,
            if_stages,
            else_stages,
            phantom: PhantomData,
        }
    }
}

/// A stage wrapper where the stages do not need to be initialized, but can be [`None`].
#[derive(Debug)]
pub struct OptionalStage<E, EM, ST, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    stages: Option<ST>,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, ST, Z> UsesState for OptionalStage<E, EM, ST, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<E, EM, ST, Z> Stage<E, EM, Z> for OptionalStage<E, EM, ST, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
    E::State: HasNestedStageStatus,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if let Some(stages) = &mut self.stages {
            stages.perform_all(fuzzer, executor, state, manager)
        } else {
            Ok(())
        }
    }

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        NestedStageRestartHelper::restart_progress_should_run(state, self)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        NestedStageRestartHelper::clear_restart_progress(state, self)
    }
}

impl<E, EM, ST, Z> OptionalStage<E, EM, ST, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor for this conditionally enabled stage.
    #[must_use]
    pub fn new(stages: Option<ST>) -> Self {
        Self {
            stages,
            phantom: PhantomData,
        }
    }

    /// Constructor for this conditionally enabled stage with set stages.
    #[must_use]
    pub fn some(stages: ST) -> Self {
        Self {
            stages: Some(stages),
            phantom: PhantomData,
        }
    }

    /// Constructor for this conditionally enabled stage, without stages set.
    #[must_use]
    pub fn none() -> Self {
        Self {
            stages: None,
            phantom: PhantomData,
        }
    }
}
