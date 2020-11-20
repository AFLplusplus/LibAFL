pub mod mutational;
pub use mutational::DefaultMutationalStage;

use crate::corpus::testcase::Testcase;
use crate::corpus::Corpus;
use crate::engines::State;
use crate::executors::Executor;
use crate::inputs::Input;
use crate::AflError;
use alloc::rc::Rc;
use core::cell::RefCell;

pub trait Stage<S, C, E, I>
where
    S: State<C, E, I>,
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    /// Run the stage
    fn perform(
        &mut self,
        testcase: Rc<RefCell<Testcase<I>>>,
        state: &mut S,
    ) -> Result<(), AflError>;
}
