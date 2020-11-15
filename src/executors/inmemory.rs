extern crate alloc;

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ffi::c_void;
use core::ptr;

use crate::executors::{Executor, ExitKind};
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::observers::Observer;
use crate::AflError;

type HarnessFunction<I> = fn(&dyn Executor<I>, &[u8]) -> ExitKind;

pub struct InMemoryExecutor<I>
where
    I: Input,
{
    observers: Vec<Box<dyn Observer>>,
    harness: HarnessFunction<I>,
    feedbacks: Vec<Box<dyn Feedback<I>>>,
}

impl<I> Into<Rc<RefCell<Self>>> for InMemoryExecutor<I>
where
    I: Input,
{
    fn into(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
}

static mut CURRENT_INMEMORY_EXECUTOR_PTR: *const c_void = ptr::null();

impl<I> Executor<I> for InMemoryExecutor<I>
where
    I: Input,
{
    fn run_target(&mut self, input: &I) -> Result<ExitKind, AflError> {
        let bytes = input.serialize()?;
        unsafe {
            CURRENT_INMEMORY_EXECUTOR_PTR = self as *const InMemoryExecutor<I> as *const c_void;
        }
        let ret = (self.harness)(self, bytes);
        unsafe {
            CURRENT_INMEMORY_EXECUTOR_PTR = ptr::null();
        }
        Ok(ret)
    }

    fn reset_observers(&mut self) -> Result<(), AflError> {
        for observer in &mut self.observers {
            observer.reset()?;
        }
        Ok(())
    }

    fn post_exec_observers(&mut self) -> Result<(), AflError> {
        self.observers
            .iter_mut()
            .map(|x| x.post_exec())
            .fold(Ok(()), |acc, x| if x.is_err() { x } else { acc })
    }

    fn add_observer(&mut self, observer: Box<dyn Observer>) {
        self.observers.push(observer);
    }

    fn observers(&self) -> &[Box<dyn Observer>] {
        &self.observers
    }

    fn feedbacks(&self) -> &[Box<dyn Feedback<I>>] {
        &self.feedbacks
    }

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>> {
        &mut self.feedbacks
    }

    fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>) {
        self.feedbacks_mut().push(feedback);
    }
}

impl<I> InMemoryExecutor<I>
where
    I: Input,
{
    pub fn new(harness_fn: HarnessFunction<I>) -> Self {
        #[cfg(feature = "std")]
        unsafe {
            os_signals::setup_crash_handlers::<I>();
        }
        InMemoryExecutor {
            observers: vec![],
            feedbacks: vec![],
            harness: harness_fn,
        }
    }
}

#[cfg(feature = "std")]
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

    use crate::executors::inmemory::CURRENT_INMEMORY_EXECUTOR_PTR;
    use crate::inputs::Input;

    pub extern "C" fn libaflrs_executor_inmem_handle_crash<I>(
        _sig: c_int,
        info: siginfo_t,
        _void: c_void,
    ) where
        I: Input,
    {
        unsafe {
            if CURRENT_INMEMORY_EXECUTOR_PTR == ptr::null() {
                println!(
                    "We died accessing addr {}, but are not in client...",
                    info.si_addr() as usize
                );
            }
        }

        #[cfg(feature = "std")]
        println!("Child crashed!");
        #[cfg(feature = "std")]
        let _ = stdout().flush();

        // TODO: LLMP
    }

    pub extern "C" fn libaflrs_executor_inmem_handle_timeout<I>(
        _sig: c_int,
        _info: siginfo_t,
        _void: c_void,
    ) where
        I: Input,
    {
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

    pub unsafe fn setup_crash_handlers<I>()
    where
        I: Input,
    {
        let mut sa: sigaction = mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        sa.sa_flags = SA_NODEFER | SA_SIGINFO;
        sa.sa_sigaction = libaflrs_executor_inmem_handle_crash::<I> as usize;
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

        sa.sa_sigaction = libaflrs_executor_inmem_handle_timeout::<I> as usize;
        if sigaction(SIGUSR2, &mut sa as *mut sigaction, ptr::null_mut()) < 0 {
            panic!("Could not set up sigusr2 handler for timeouts");
        }
    }
}

#[cfg(feature = "std")]
#[cfg(unix)]
use unix_signals as os_signals;
#[cfg(feature = "std")]
#[cfg(not(unix))]
compile_error!("InMemoryExecutor not yet supported on this OS");

#[cfg(test)]
mod tests {

    extern crate alloc;
    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::Input;
    use crate::observers::Observer;
    use crate::AflError;
    use alloc::boxed::Box;

    #[derive(Clone)]
    struct NopInput {}
    impl Input for NopInput {
        fn serialize(&self) -> Result<&[u8], AflError> {
            Ok("NOP".as_bytes())
        }
        fn deserialize(_buf: &[u8]) -> Result<Self, AflError> {
            Ok(Self {})
        }
    }

    struct Nopserver {}

    impl Observer for Nopserver {
        fn reset(&mut self) -> Result<(), AflError> {
            Err(AflError::Unknown("Nop reset, testing only".into()))
        }
        fn post_exec(&mut self) -> Result<(), AflError> {
            Err(AflError::Unknown("Nop exec, testing only".into()))
        }
    }

    #[cfg(feature = "std")]
    fn test_harness_fn_nop(_executor: &dyn Executor<NopInput>, buf: &[u8]) -> ExitKind {
        println! {"Fake exec with buf of len {}", buf.len()};
        ExitKind::Ok
    }

    #[cfg(not(feature = "std"))]
    fn test_harness_fn_nop(_executor: &dyn Executor<NopInput>, _buf: &[u8]) -> ExitKind {
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
        let mut input = NopInput {};
        assert!(in_mem_executor.run_target(&mut input).is_ok());
    }
}
