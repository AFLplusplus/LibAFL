pub mod mutational;
pub use mutational::{MutationalStage, StdMutationalStage};

//pub mod power;
//pub use power::PowerMutationalStage;

use crate::{
    bolts::tuples::TupleList, events::EventManager, executors::Executor, inputs::Input, Error,
};

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<CS, E, EM, I, S>
where
    EM: EventManager<I, S>,
    E: Executor<I>,
    I: Input,
{
    /// Run the stage
    fn perform(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

pub trait StagesTuple<CS, E, EM, I, S>
where
    EM: EventManager<I, S>,
    E: Executor<I>,
    I: Input,
{
    fn perform_all(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

impl<CS, E, EM, I, S> StagesTuple<CS, E, EM, I, S> for ()
where
    EM: EventManager<I, S>,
    E: Executor<I>,
    I: Input,
{
    fn perform_all(
        &mut self,
        _: &mut S,
        _: &mut E,
        _: &mut EM,
        _: &CS,
        _: usize,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, CS, E, EM, I, S> StagesTuple<CS, E, EM, I, S> for (Head, Tail)
where
    Head: Stage<CS, E, EM, I, S>,
    Tail: StagesTuple<CS, E, EM, I, S> + TupleList,
    EM: EventManager<I, S>,
    E: Executor<I>,
    I: Input,
{
    fn perform_all(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.0
            .perform(state, executor, manager, scheduler, corpus_idx)?;
        self.1
            .perform_all(state, executor, manager, scheduler, corpus_idx)
    }
}
