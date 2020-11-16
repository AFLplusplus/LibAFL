pub mod mutational;
pub use mutational::DefaultMutationalStage;

use crate::corpus::testcase::Testcase;
use crate::corpus::Corpus;
use crate::inputs::Input;
use crate::AflError;
use alloc::rc::Rc;
use core::cell::RefCell;

pub trait Stage<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    /// Run the stage
    fn perform(
        &mut self,
        testcase: Rc<RefCell<Testcase<I>>>,
        corpus: &mut C,
    ) -> Result<(), AflError>;
}
