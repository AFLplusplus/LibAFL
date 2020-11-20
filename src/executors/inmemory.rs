use alloc::rc::Rc;
use core::cell::RefCell;
use core::ffi::c_void;
use core::ptr;

use crate::executors::{Executor, ExitKind};
use crate::inputs::Input;
use crate::AflError;

type HarnessFunction<I> = fn(&dyn Executor<I>, &[u8]) -> ExitKind;

pub struct InMemoryExecutor<I>
where
    I: Input,
{
    harness: HarnessFunction<I>,
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

    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::Input;
    use crate::AflError;

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

    #[cfg(feature = "std")]
    fn test_harness_fn_nop(_executor: &dyn Executor<NopInput>, buf: &[u8]) -> ExitKind {
        println!("Fake exec with buf of len {}", buf.len());
        ExitKind::Ok
    }

    #[cfg(not(feature = "std"))]
    fn test_harness_fn_nop(_executor: &dyn Executor<NopInput>, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_inmem_exec() {
        let mut in_mem_executor = InMemoryExecutor::new(test_harness_fn_nop);
        let mut input = NopInput {};
        assert!(in_mem_executor.run_target(&mut input).is_ok());
    }
}
