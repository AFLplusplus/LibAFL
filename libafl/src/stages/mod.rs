/*!
A [`Stage`] is a technique used during fuzzing, working on one [`crate::corpus::Corpus`] entry, and potentially altering it or creating new entries.
A well-known [`Stage`], for example, is the mutational stage, running multiple [`crate::mutators::Mutator`]s against a [`crate::corpus::Testcase`], potentially storing new ones, according to [`crate::feedbacks::Feedback`].
Other stages may enrich [`crate::corpus::Testcase`]s with metadata.
*/

/// Mutational stage is the normal fuzzing stage,
//pub mod mutational;

//pub use mutational::{MutationalStage, StdMutationalStage};

//pub mod power;
//pub use power::PowerMutationalStage;
use crate::{
    bolts::tuples::TupleList, events::EventManager, executors::Executor, inputs::Input,
    state::State, Error,
};

/// A stage is one step in the fuzzing process.
/// Multiple stages will be scheduled one by one for each input.
pub trait Stage<E, EM, I, S, Z>
where
    E: Executor<I>,
    EM: EventManager<E, I, S, Z>,
    I: Input,
    S: State,
{
    /// Run the stage
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

/// A tuple holding all `Stages` used for fuzzing.
pub trait StagesTuple<E, EM, I, S, Z>
where
    E: Executor<I>,
    EM: EventManager<E, I, S, Z>,
    I: Input,
    S: State,
{
    /// Performs all `Stages` in this tuple
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error>;
}

impl<E, EM, I, S, Z> StagesTuple<E, EM, I, S, Z> for ()
where
    E: Executor<I>,
    EM: EventManager<E, I, S, Z>,
    I: Input,
    S: State,
{
    fn perform_all(
        &mut self,
        _: &mut Z,
        _: &mut E,
        _: &mut S,
        _: &mut EM,
        _: usize,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, E, EM, I, S, Z> StagesTuple<E, EM, I, S, Z> for (Head, Tail)
where
    Head: Stage<E, EM, I, S, Z>,
    Tail: StagesTuple<E, EM, I, S, Z> + TupleList,
    E: Executor<I>,
    EM: EventManager<E, I, S, Z>,
    I: Input,
    S: State,
{
    fn perform_all(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        // Perform the current stage
        self.0
            .perform(fuzzer, executor, state, manager, corpus_idx)?;

        // Execute the remaining stages
        self.1
            .perform_all(fuzzer, executor, state, manager, corpus_idx)
    }
}
