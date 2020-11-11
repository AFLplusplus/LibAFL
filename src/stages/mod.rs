extern crate alloc;
pub mod mutational;
pub use mutational::DefaultMutationalStage;

use crate::corpus::Testcase;
use crate::inputs::Input;
use crate::AflError;

use alloc::rc::Rc;
use core::cell::RefCell;

pub trait Stage<I>
where
    I: Input,
{
    /// Run the stage
    fn perform(&mut self, entry: &Rc<RefCell<Testcase<I>>>) -> Result<(), AflError>;
}
