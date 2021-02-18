pub mod mutational;
pub use mutational::StdMutationalStage;

use crate::{
    bolts::tuples::TupleList,
    corpus::Corpus,
    events::EventManager,
    executors::{Executor},
    inputs::Input,
    Error,
};

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<I>
where
    I: Input
{
    /// Run the stage
    fn perform<E, EM, S>(
        &self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>
    where
        EM: EventManager<I>,
        E: Executor<I>;
}

pub trait StagesTuple<I>
where
    I: Input
{
    fn perform_all<E, EM, S>(
        &self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>
    where
        EM: EventManager<I>,
        E: Executor<I>;
}

impl<I> StagesTuple<I> for ()
where
    I: Input
{
    fn perform_all<E, EM, S>(
        &self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>
    where
        EM: EventManager<I>,
        E: Executor<I>
    {
        Ok(())
    }
}

impl<Head, Tail, I> StagesTuple<I> for (Head, Tail)
where
    Head: Stage,
    Tail: StagesTuple + TupleList,
    I: Input
{
    fn perform_all<E, EM, S>(
        &self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>
    where
        EM: EventManager<I>,
        E: Executor<I>
    {
        self.0.perform(executor, state, manager, corpus_idx)?;
        self.1 .perform_all(executor, state, manager, corpus_idx)
    }
}
