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

impl InMemoryExecutor {
    fn new(harness_fn: HarnessFunction) -> InMemoryExecutor {
        InMemoryExecutor {
            base: ExecutorBase {
                observers: vec![],
                cur_input: Option::None,
            },
            harness: harness_fn,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::executors::{Executor, ExitKind, InMemoryExecutor};
    use crate::observers::Observer;
    use crate::AflError;

    struct Nopserver {}

    impl Observer for Nopserver {
        fn reset(&mut self) -> Result<(), AflError> {
            Err(AflError::Unknown)
        }
        fn post_exec(&mut self) -> Result<(), AflError> {
            Err(AflError::Unknown)
        }
    }

    fn test_harness_fn_nop(_executor: &dyn Executor, buf: &[u8]) -> ExitKind {
        println! {"Fake exec with buf of len {}", buf.len()};
        ExitKind::Ok
    }

    #[test]
    fn test_inmem_post_exec() {
        let mut in_mem_executor = InMemoryExecutor::new(test_harness_fn_nop);
        let nopserver = Nopserver {};
        in_mem_executor.add_observer(Box::new(nopserver));
        assert_eq!(in_mem_executor.post_exec_observers().is_err(), true);
    }
}
