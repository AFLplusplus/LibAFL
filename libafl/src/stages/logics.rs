//! Stage wrappers that add logics to stage list

use core::marker::PhantomData;

use crate::{
    corpus::CorpusId,
    Error,
    state::UsesState,
    stages::{Stage, StagesTuple},
};


/// Perform the stage if closure evaluates to true
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
    stages: ST,
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
            self.stages.perform_all(fuzzer, executor, state, manager, corpus_idx)?
        }
        Ok(())
    }
}