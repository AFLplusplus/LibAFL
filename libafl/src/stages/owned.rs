//! A dynamic collection of owned Stages

use alloc::{boxed::Box, vec::Vec};

use crate::{
    bolts::anymap::AsAny,
    corpus::CorpusId,
    stages::{Stage, StagesTuple},
    state::UsesState,
    Error,
};

/// Combine `Stage` and `AsAny`
pub trait AnyStage<E, EM, Z>: Stage<E, EM, Z> + AsAny
where
    E: UsesState<State = Self::State>,
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
}

/// An owned list of `Observer` trait objects
#[derive(Default)]
#[allow(missing_debug_implementations)]
pub struct StagesOwnedList<E, EM, Z>
where
    E: UsesState,
{
    /// The named trait objects map
    #[allow(clippy::type_complexity)]
    pub list: Vec<Box<dyn AnyStage<E, EM, Z, State = E::State, Input = E::Input>>>,
}

impl<E, EM, Z> StagesTuple<E, EM, E::State, Z> for StagesOwnedList<E, EM, Z>
where
    E: UsesState,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut E::State,
        manager: &mut EM,
        corpus_idx: CorpusId,
    ) -> Result<(), Error> {
        for s in &mut self.list {
            s.perform(fuzzer, executor, state, manager, corpus_idx)?;
        }
        Ok(())
    }
}

impl<E, EM, Z> StagesOwnedList<E, EM, Z>
where
    E: UsesState,
{
    /// Create a new instance
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn new(list: Vec<Box<dyn AnyStage<E, EM, Z, Input = E::Input, State = E::State>>>) -> Self {
        Self { list }
    }
}
