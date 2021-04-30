//! Mutators mutate input during fuzzing.

pub mod scheduled;
pub use scheduled::*;
pub mod mutations;
pub use mutations::*;
pub mod token_mutations;
pub use token_mutations::*;

use crate::{
    bolts::tuples::{HasLen, Named},
    inputs::Input,
    Error,
};

// TODO mutator stats method that produces something that can be sent with the NewTestcase event
// We can use it to report which mutations generated the testcase in the broker logs

/// The result of a mutation.
/// If the mutation got skipped, the target
/// will not be executed with the returned input.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MutationResult {
    Mutated,
    Skipped,
}

/// A mutator takes input, and mutates it.
/// Simple as that.
pub trait Mutator<I, S>
where
    I: Input,
{
    /// Mutate a given input
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error>;

    /// Post-process given the outcome of the execution
    fn post_exec(
        &mut self,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

pub trait MutatorsTuple<I, S>: HasLen
where
    I: Input,
{
    fn mutate_all(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error>;

    fn post_exec_all(
        &mut self,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error>;

    fn get_and_mutate(
        &mut self,
        index: usize,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error>;

    fn get_and_post_exec(
        &mut self,
        index: usize,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error>;
}

impl<I, S> MutatorsTuple<I, S> for ()
where
    I: Input,
{
    fn mutate_all(
        &mut self,
        _state: &mut S,
        _input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        Ok(MutationResult::Skipped)
    }

    fn post_exec_all(
        &mut self,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn get_and_mutate(
        &mut self,
        _index: usize,
        _state: &mut S,
        _input: &mut I,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        Ok(MutationResult::Skipped)
    }

    fn get_and_post_exec(
        &mut self,
        _index: usize,
        _state: &mut S,
        _stage_idx: i32,
        _corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, I, S> MutatorsTuple<I, S> for (Head, Tail)
where
    Head: Mutator<I, S> + Named,
    Tail: MutatorsTuple<I, S>,
    I: Input,
{
    fn mutate_all(
        &mut self,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let r = self.0.mutate(state, input, stage_idx)?;
        if self.1.mutate_all(state, input, stage_idx)? == MutationResult::Mutated {
            Ok(MutationResult::Mutated)
        } else {
            Ok(r)
        }
    }

    fn post_exec_all(
        &mut self,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        self.0.post_exec(state, stage_idx, corpus_idx)?;
        self.1.post_exec_all(state, stage_idx, corpus_idx)
    }

    fn get_and_mutate(
        &mut self,
        index: usize,
        state: &mut S,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        if index == 0 {
            self.0.mutate(state, input, stage_idx)
        } else {
            self.1.get_and_mutate(index - 1, state, input, stage_idx)
        }
    }

    fn get_and_post_exec(
        &mut self,
        index: usize,
        state: &mut S,
        stage_idx: i32,
        corpus_idx: Option<usize>,
    ) -> Result<(), Error> {
        if index == 0 {
            self.0.post_exec(state, stage_idx, corpus_idx)
        } else {
            self.1
                .get_and_post_exec(index - 1, state, stage_idx, corpus_idx)
        }
    }
}
