pub mod aflengine;

use crate::AflError;
use crate::inputs::Input;
use crate::corpus::testcase::Testcase;

use std::cell::RefCell;
use std::rc::Rc;

pub trait Engine<'a, I> where I: Input {

    fn execute(&mut self, input: &mut I, entry: Rc<RefCell<Testcase<I>>>) -> Result<bool, AflError>;

}
