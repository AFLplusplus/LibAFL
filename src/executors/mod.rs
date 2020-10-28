use crate::inputs::Input;
use crate::observers::Observer;
use crate::AflError;

use std::ptr;

pub enum ExitKind {
    Ok,
    Crash,
    OOM,
    Timeout,
}

pub trait Executor {
    fn run_target(&mut self) -> Result<ExitKind, AflError>;

    fn place_input(&mut self, input: Box<dyn Input>) -> Result<(), AflError>;

    fn reset_observers(&mut self) -> Result<(), AflError>;

    fn post_exec_observers(&mut self) -> Result<(), AflError>;

    fn add_observer(&mut self, observer: Box<dyn Observer>);
}

// TODO abstract classes? how?
pub struct ExecutorBase {
    observers: Vec<Box<dyn Observer>>,
    cur_input: Option<Box<dyn Input>>,
}

type HarnessFunction = fn(&dyn Executor, &[u8]) -> ExitKind;

pub struct InMemoryExecutor {
    base: ExecutorBase,
    harness: HarnessFunction,
}

static mut CURRENT_INMEMORY_EXECUTOR_PTR: *const InMemoryExecutor = ptr::null();

impl Executor for InMemoryExecutor {
    fn run_target(&mut self) -> Result<ExitKind, AflError> {
        let bytes = match self.base.cur_input.as_ref() {
            Some(i) => i.serialize(),
            None => return Err(AflError::Unknown),
        };
        unsafe {
            CURRENT_INMEMORY_EXECUTOR_PTR = self as *const InMemoryExecutor;
        }
        let ret = match bytes {
            Ok(b) => Ok((self.harness)(self, b)),
            Err(e) => Err(e),
        };
        unsafe {
            CURRENT_INMEMORY_EXECUTOR_PTR = ptr::null();
        }
        ret
    }

    fn place_input(&mut self, input: Box<dyn Input>) -> Result<(), AflError> {
        self.base.cur_input = Some(input);
        Ok(())
    }

    fn reset_observers(&mut self) -> Result<(), AflError> {
        for observer in &mut self.base.observers {
            observer.reset()?;
        }
        Ok(())
    }

    fn post_exec_observers(&mut self) -> Result<(), AflError> {
        self.base
            .observers
            .iter_mut()
            .map(|x| x.post_exec())
            .fold(Ok(()), |acc, x| if x.is_err() { x } else { acc })
    }

    fn add_observer(&mut self, observer: Box<dyn Observer>) {
        self.base.observers.push(observer);
    }
}
