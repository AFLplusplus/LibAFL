//! A dynamic collection of owned Stages

use alloc::{boxed::Box, vec::Vec};

use crate::{
    bolts::anymap::AsAny,
    events::Event,
    prelude::State,
    stages::{Stage, StagesTuple},
    Error,
};

/// Combine `Stage` and `AsAny`
pub trait AnyStage: Stage + AsAny {}

/// An owned list of `Observer` trait objects
#[derive(Default)]
#[allow(missing_debug_implementations)]
pub struct StagesOwnedList {
    /// The named trait objects map
    pub list: Vec<
        Box<
            dyn AnyStage<
                Input = <<Self as StagesTuple>::State as State>::Input,
                State = <Self as StagesTuple>::State,
                Fuzzer = <Self as StagesTuple>::Fuzzer,
                Executor = <Self as StagesTuple>::Executor,
                EventManager = <Self as StagesTuple>::EventManager,
            >,
        >,
    >,
}

impl StagesTuple for StagesOwnedList {
    fn perform_all(
        &mut self,
        fuzzer: &mut Self::Fuzzer,
        executor: &mut Self::Executor,
        state: &mut Self::State,
        manager: &mut Self::EventManager,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        for s in &mut self.list {
            s.perform(fuzzer, executor, state, manager, corpus_idx)?;
        }
        Ok(())
    }
}

impl StagesOwnedList {
    /// Create a new instance
    #[must_use]
    pub fn new(
        list: Vec<
            Box<
                dyn AnyStage<
                    Input = <<Self as StagesTuple>::State as State>::Input,
                    State = <Self as StagesTuple>::State,
                    Fuzzer = <Self as StagesTuple>::Fuzzer,
                    Executor = <Self as StagesTuple>::Executor,
                    EventManager = <Self as StagesTuple>::EventManager,
                >,
            >,
        >,
    ) -> Self {
        Self { list }
    }
}
