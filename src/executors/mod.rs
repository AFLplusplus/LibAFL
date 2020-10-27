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

    fn place_input(&mut self, input: Box<dyn Input>) -> Result<(), AflError>;

}

// TODO abstract classes? how?
pub struct ExecutorBase {

    observers: Vec<Box<dyn Observer>>,
    cur_input: Box<dyn Input>

}

type HarnessFunction = fn(&dyn Executor, &[u8]) -> ExitKind;

pub struct InMemoryExecutor {

    base: ExecutorBase,
    harness: HarnessFunction,

}

static mut CURRENT_INMEMORY_EXECUTOR: Option<&InMemoryExecutor> = None;

impl Executor for InMemoryExecutor {

    fn run_target(&mut self) -> Result<ExitKind, AflError> {
        let bytes = self.base.cur_input.serialize();
        unsafe { CURRENT_INMEMORY_EXECUTOR = Some(self); }
        let outcome = match bytes {
            Ok(b) => Ok((self.harness)(self, b)),
            Err(e) => Err(e)
        };
        unsafe { CURRENT_INMEMORY_EXECUTOR = None; }
        outcome
    }

    fn place_input(&mut self, input: Box<dyn Input>) -> Result<(), AflError> {
        self.base.cur_input = input;
        Ok(())
    }

}