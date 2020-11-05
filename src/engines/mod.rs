pub mod aflengine;

use crate::corpus::testcase::Testcase;
use crate::inputs::Input;
use crate::AflError;

use std::cell::RefCell;
use std::rc::Rc;

pub trait Engine<'a, I>
where
    I: Input,
{
    fn execute(&mut self, input: &mut I, entry: Rc<RefCell<Testcase<I>>>)
        -> Result<bool, AflError>;
}
