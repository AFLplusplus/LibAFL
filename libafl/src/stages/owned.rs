//! A dynamic collection of owned Stages

use crate::{
    bolts::anymap::AsAny,
    stages::{Stage, StagesTuple},
    Error,
};

/// Combine `Stage` and `AsAny`
pub trait AnyStage<E, EM, S, Z>: Stage<E, EM, S, Z> + AsAny {}

/// An owned list of `Observer` trait objects
#[derive(Default)]
#[allow(missing_debug_implementations)]
pub struct StagesOwnedList<E, EM, S, Z> {
    /// The named trait objects map
    pub list: Vec<Box<dyn AnyStage<E, EM, S, Z>>>,
}

impl<E, EM, S, Z> StagesTuple<E, EM, S, Z> for StagesOwnedList<E, EM, S, Z> {
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        for s in &mut self.list {
            s.perform(fuzzer, executor, state, manager, corpus_idx)?;
        }
        Ok(())
    }
}

impl<E, EM, S, Z> StagesOwnedList<E, EM, S, Z> {
    /// Create a new instance
    #[must_use]
    pub fn new(list: Vec<Box<dyn AnyStage<E, EM, S, Z>>>) -> Self {
        Self { list }
    }
}
