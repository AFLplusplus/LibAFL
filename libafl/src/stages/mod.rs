pub mod mutational;
pub use mutational::StdMutationalStage;

use crate::{
    bolts::tuples::TupleList, corpus::Corpus, events::EventManager, executors::Executor,
    inputs::Input, Error,
};

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, F, S> {
    /// Run the stage
    fn perform(
        &self,
        fuzzer: &F,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

pub trait StagesTuple<E, EM, F, S> {
    fn perform_all(
        &self,
        fuzzer: &F,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

impl<E, EM, F, S> StagesTuple<E, EM, F, S> for () {
    fn perform_all(
        &self,
        fuzzer: &F,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, E, EM, F, S> StagesTuple<E, EM, F, S> for (Head, Tail)
where
    Head: Stage<E, EM, F, S>,
    Tail: StagesTuple<E, EM, F, S> + TupleList,
{
    fn perform_all(
        &self,
        fuzzer: &F,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.0
            .perform(fuzzer, state, executor, manager, corpus_idx)?;
        self.1
            .perform_all(fuzzer, state, executor, manager, corpus_idx)
    }
}
