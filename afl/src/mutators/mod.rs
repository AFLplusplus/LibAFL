pub mod scheduled;
pub use scheduled::ComposedByMutations;
pub use scheduled::HavocBytesMutator;
pub use scheduled::ScheduledMutator;
pub use scheduled::StdScheduledMutator;

use alloc::rc::Rc;
use core::cell::RefCell;

use crate::corpus::Corpus;
use crate::corpus::Testcase;
use crate::inputs::Input;
use crate::utils::Rand;
use crate::AflError;

pub trait Mutator<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Mutate a given input
    fn mutate(
        &mut self,
        rand: &mut R,
        corpus: &mut C,
        input: &mut I,
        stage_idx: i32,
    ) -> Result<(), AflError>;

    /// Post-process given the outcome of the execution
    fn post_exec(
        &mut self,
        _is_interesting: bool,
        _new_testcase: Option<Rc<RefCell<Testcase<I>>>>,
        _stage_idx: i32,
    ) -> Result<(), AflError> {
        Ok(())
    }
}
