pub mod inmemory;
pub use inmemory::{InMemoryExecutor};

use crate::inputs::Input;
use crate::observers::Observer;
use crate::AflError;

pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout,
}

pub trait Executor {
    fn run_target(&mut self) -> Result<ExitKind, AflError>;

    fn place_input(&mut self, input: Box<dyn Input>) -> Result<(), AflError>;

    fn get_input(&self) -> Option<& Box<dyn Input>>;

    fn reset_observers(&mut self) -> Result<(), AflError>;

    fn post_exec_observers(&mut self) -> Result<(), AflError>;

    fn add_observer(&mut self, observer: Box<dyn Observer>);

    fn get_observers(&self) -> &Vec<Box<dyn Observer>>;
}

// TODO abstract classes? how?
pub struct ExecutorBase {
    observers: Vec<Box<dyn Observer>>,
    cur_input: Option<Box<dyn Input>>,
}
