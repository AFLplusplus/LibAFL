pub mod mutational;
pub use mutational::StdMutationalStage;

use crate::{
    bolts::tuples::TupleList, events::EventManager, executors::Executor, inputs::Input, Error,
};

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, I, S>
where
    EM: EventManager<I, S>,
    E: Executor<I>,
    I: Input,
{
    /// Run the stage
    fn perform(
        &self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

pub trait StagesTuple<E, EM, I, S>
where
    EM: EventManager<I, S>,
    E: Executor<I>,
    I: Input,
{
    fn perform_all(
        &self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

impl<E, EM, I, S> StagesTuple<E, EM, I, S> for ()
where
    EM: EventManager<I, S>,
    E: Executor<I>,
    I: Input,
{
    fn perform_all(&self, _: &mut S, _: &mut E, _: &mut EM, _: usize) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, E, EM, I, S> StagesTuple<E, EM, I, S> for (Head, Tail)
where
    Head: Stage<E, EM, I, S>,
    Tail: StagesTuple<E, EM, I, S> + TupleList,
    EM: EventManager<I, S>,
    E: Executor<I>,
    I: Input,
{
    fn perform_all(
        &self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.0.perform(state, executor, manager, corpus_idx)?;
        self.1.perform_all(state, executor, manager, corpus_idx)
    }
}
