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

#[cfg(unix)]
pub mod unix_signals {

    extern crate libc;
    use self::libc::{c_int, c_void, sigaction, siginfo_t};
    // Unhandled signals: SIGALRM, SIGHUP, SIGINT, SIGKILL, SIGQUIT, SIGTERM
    use self::libc::{
        SA_NODEFER, SA_SIGINFO, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGPIPE, SIGSEGV, SIGUSR2,
    };
    use std::io::{stdout, Write}; // Write brings flush() into scope
    use std::{mem, process, ptr};

    use crate::executors::CURRENT_INMEMORY_EXECUTOR_PTR;

    pub extern "C" fn libaflrs_executor_inmem_handle_crash(
        _sig: c_int,
        info: siginfo_t,
        _void: c_void,
    ) {
        unsafe {
            if CURRENT_INMEMORY_EXECUTOR_PTR == ptr::null() {
                println!(
                    "We died accessing addr {}, but are not in client...",
                    info.si_addr() as usize
                );
            }
        }
        // TODO: LLMP
        println!("Child crashed!");
        let _ = stdout().flush();
    }

    pub extern "C" fn libaflrs_executor_inmem_handle_timeout(
        _sig: c_int,
        _info: siginfo_t,
        _void: c_void,
    ) {
        dbg!("TIMEOUT/SIGUSR2 received");
        unsafe {
            if CURRENT_INMEMORY_EXECUTOR_PTR == ptr::null() {
                dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing.");
                return;
            }
        }
        // TODO: send LLMP.
        println!("Timeout in fuzz run.");
        let _ = stdout().flush();
        process::abort();
    }

    pub unsafe fn setup_crash_handlers() {
        let mut sa: sigaction = mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        sa.sa_flags = SA_NODEFER | SA_SIGINFO;
        sa.sa_sigaction = libaflrs_executor_inmem_handle_crash as usize;
        for (sig, msg) in &[
            (SIGSEGV, "segfault"),
            (SIGBUS, "sigbus"),
            (SIGABRT, "sigabrt"),
            (SIGILL, "illegal instruction"),
            (SIGFPE, "fp exception"),
            (SIGPIPE, "pipe"),
        ] {
            if sigaction(*sig, &mut sa as *mut sigaction, ptr::null_mut()) < 0 {
                panic!("Could not set up {} handler", &msg);
            }
        }

        sa.sa_sigaction = libaflrs_executor_inmem_handle_timeout as usize;
        if sigaction(SIGUSR2, &mut sa as *mut sigaction, ptr::null_mut()) < 0 {
            panic!("Could not set up sigusr2 handler for timeouts");
        }
    }
}

#[cfg(unix)]
use unix_signals as os_signals;
#[cfg(not(unix))]
compile_error!("InMemoryExecutor not yet supported on this OS");

impl Executor for InMemoryExecutor {
    fn run_target(&mut self) -> Result<ExitKind, AflError> {
        let bytes = match self.base.cur_input.as_ref() {
            Some(i) => i.serialize(),
            None => return Err(AflError::Unknown),
        };
        unsafe {
            CURRENT_INMEMORY_EXECUTOR_PTR = self as *const InMemoryExecutor;
            os_signals::setup_crash_handlers();
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
    pub fn new(harness_fn: HarnessFunction) -> InMemoryExecutor {
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
    use crate::inputs::Input;
    use crate::observers::Observer;
    use crate::AflError;

    struct NopInput {}
    impl Input for NopInput {
        fn serialize(&self) -> Result<&[u8], AflError> {
            Ok("NOP".as_bytes())
        }
        fn deserialize(&mut self, _buf: &[u8]) -> Result<(), AflError> {
            Ok(())
        }
    }

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

    #[test]
    fn test_inmem_exec() {
        let mut in_mem_executor = InMemoryExecutor::new(test_harness_fn_nop);
        let input = NopInput {};
        assert!(in_mem_executor.place_input(Box::new(input)).is_ok());
        assert!(in_mem_executor.run_target().is_ok());
    }
}
