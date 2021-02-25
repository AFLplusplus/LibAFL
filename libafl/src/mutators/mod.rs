//! Mutators mutate input during fuzzing.

pub mod scheduled;
pub use scheduled::*;
pub mod mutations;
pub use mutations::*;
pub mod token_mutations;
pub use token_mutations::*;

use crate::{inputs::Input, Error};

// TODO mutator stats method that produces something that can be sent with the NewTestcase event
// We can use it to report which mutations generated the testcase in the broker logs

/// A mutator takes input, and mutates it.
/// Simple as that.
pub trait Mutator<I, S>
where
    I: Input,
{
    /// Mutate a given input
    fn mutate(&self, state: &mut S, input: &mut I, stage_idx: i32) -> Result<(), Error>;

    /// Post-process given the outcome of the execution
    fn post_exec(
        &self,
        _state: &mut S,
        _is_interesting: u32,
        _stage_idx: i32,
    ) -> Result<(), Error> {
        Ok(())
    }
}
