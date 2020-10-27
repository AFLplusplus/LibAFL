use crate::AflError;
use crate::inputs::Input;
use crate::observers::Observer;

pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout
}

pub trait Executor {

    fn run_target(&mut self) -> Result<ExitKind, AflError>;

    fn place_input(&mut self, entry: Box<dyn Input>) -> Result<(), AflError>;

}

// TODO abstract classes? how?
pub struct ExecutorBase {

    observers: Vec<Box<dyn Observer>>,
    cur_input: Box<dyn Input>

}