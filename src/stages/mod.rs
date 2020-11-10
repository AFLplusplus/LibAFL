pub mod mutational;
pub use mutational::DefaultMutationalStage;

use crate::corpus::Testcase;
use crate::inputs::Input;
use crate::AflError;

use core::cell::RefCell;
use std::rc::Rc;

pub trait Stage<I>
where
    I: Input,
{
    /// Run the stage
    fn perform(&mut self, entry: &Rc<RefCell<Testcase<I>>>) -> Result<(), AflError>;
}
