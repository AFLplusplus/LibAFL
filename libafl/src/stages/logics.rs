//! Stage wrappers that add logics to stage list

use core::marker::PhantomData;

use crate::{
    corpus::CorpusId,
    stages::{Stage, StagesTuple},
    state::UsesState,
    Error,
};

/// Perform the stage if closure evaluates to true
#[derive(Debug)]
pub struct IfElseStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    closure: CB,
    if_stages: ST,
    else_stages: ST,
    phantom: PhantomData<(E, EM, Z)>,
}

impl<CB, E, EM, ST, Z> UsesState for IfElseStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    type State = E::State;
}

impl<CB, E, EM, ST, Z> Stage<E, EM, Z> for IfElseStage<CB, E, EM, ST, Z>
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
        else{
            self.else_stages
                .perform_all(fuzzer, executor, state, manager, corpus_idx)?;
        }
        Ok(())
    }
}

impl<CB, E, EM, ST, Z> IfElseStage<CB, E, EM, ST, Z>
where
    CB: FnMut(&mut Z, &mut E, &mut E::State, &mut EM, CorpusId) -> Result<bool, Error>,
    E: UsesState,
    EM: UsesState<State = E::State>,
    ST: StagesTuple<E, EM, E::State, Z>,
    Z: UsesState<State = E::State>,
{
    /// Constructor
    pub fn new(closure: CB, if_stages: ST, else_stages: ST) -> Self {
        Self {
            closure,
            if_stages,
            else_stages,
            phantom: PhantomData,
        }
    }
}
