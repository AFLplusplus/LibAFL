//! Stage wrappers that add logics to stage list

use core::marker::PhantomData;

use crate::{
    corpus::CorpusId,
    stages::{Stage, StagesTuple},
    state::UsesState,
    Error,
};

#[derive(Debug)]
/// Perform the stage while the closure evaluates to true
pub struct WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
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
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST, Z> Stage<E, EM, Z> for WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        while (self.closure)(fuzzer, executor, state, manager, corpus_idx)? {
            self.stages
                .perform_all(fuzzer, executor, state, manager, corpus_idx)?;
        }
        Ok(())
    }
}

impl<CB, E, EM, ST, Z> WhileStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
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
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
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
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST, Z> Stage<E, EM, Z> for IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        if (self.closure)(fuzzer, executor, state, manager, corpus_idx)? {
            self.if_stages
                .perform_all(fuzzer, executor, state, manager, corpus_idx)?;
        }
        Ok(())
    }
}

impl<CB, E, EM, ST, Z> IfStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
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
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
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
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
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
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST1: StagesTuple<E, EM, E::State, Z>,
    ST2: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        if (self.closure)(fuzzer, executor, state, manager, corpus_idx)? {
            self.if_stages
                .perform_all(fuzzer, executor, state, manager, corpus_idx)?;
        } else {
            self.else_stages
                .perform_all(fuzzer, executor, state, manager, corpus_idx)?;
        }
        Ok(())
    }
}

impl<CB, E, EM, ST1, ST2, Z> IfElseStage<CB, E, EM, ST1, ST2, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
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
