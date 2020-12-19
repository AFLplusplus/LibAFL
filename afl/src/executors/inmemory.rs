use core::ffi::c_void;
use core::ptr;

use crate::executors::{Executor, ExitKind, HasObservers};
use crate::inputs::{HasTargetBytes, Input};
use crate::observers::ObserversTuple;
use crate::tuples::Named;
use crate::AflError;

/// The (unsafe) pointer to the current inmem input, for the current run.
/// This is neede for certain non-rust side effects, as well as unix signal handling.
static mut CURRENT_INPUT_PTR: *const c_void = ptr::null();

/// The inmem executor harness
type HarnessFunction<I> = fn(&dyn Executor<I>, &[u8]) -> ExitKind;

/// The inmem executor simply calls a target function, then returns afterwards.
pub struct InMemoryExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    harness: HarnessFunction<I>,
    observers: OT,
    name: &'static str,
}

impl<I, OT> Executor<I> for InMemoryExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, AflError> {
        let bytes = input.target_bytes();
        unsafe {
            CURRENT_INPUT_PTR = input as *const _ as *const c_void;
        }
        let ret = (self.harness)(self, bytes.as_slice());
        unsafe {
            CURRENT_INPUT_PTR = ptr::null();
        }
        Ok(ret)
    }
}

impl<I, OT> Named for InMemoryExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        self.name
    }
}

impl<I, OT> HasObservers<OT> for InMemoryExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn observers(&self) -> &OT {
        &self.observers
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<I, OT> InMemoryExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(name: &'static str, harness_fn: HarnessFunction<I>, observers: OT) -> Self {
        Self {
            harness: harness_fn,
            observers: observers,
            name: name,
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

    use crate::corpus::Corpus;
    use crate::events::EventManager;
    use crate::executors::inmemory::CURRENT_INPUT_PTR;
    use crate::executors::Executor;
    use crate::feedbacks::FeedbacksTuple;
    use crate::inputs::Input;
    use crate::observers::ObserversTuple;
    use crate::utils::Rand;

    static mut EVENT_MANAGER_PTR: *mut c_void = ptr::null_mut();

    pub unsafe extern "C" fn libaflrs_executor_inmem_handle_crash<EM, C, E, OT, FT, I, R>(
        _sig: c_int,
        info: siginfo_t,
        _void: c_void,
    ) where
        EM: EventManager<C, E, OT, FT, I, R>,
        C: Corpus<I, R>,
        E: Executor<I>,
        OT: ObserversTuple,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
        if CURRENT_INPUT_PTR == ptr::null() {
            println!(
                "We died accessing addr {}, but are not in client...",
                info.si_addr() as usize
            );
        }

        #[cfg(feature = "std")]
        println!("Child crashed!");
        #[cfg(feature = "std")]
        let _ = stdout().flush();

        let input = (CURRENT_INPUT_PTR as *const I).as_ref().unwrap();
        let manager = (EVENT_MANAGER_PTR as *mut EM).as_mut().unwrap();

        manager.crash(input).expect("Error in sending Crash event");

        std::process::exit(139);
    }

    pub unsafe extern "C" fn libaflrs_executor_inmem_handle_timeout<EM, C, E, OT, FT, I, R>(
        _sig: c_int,
        _info: siginfo_t,
        _void: c_void,
    ) where
        EM: EventManager<C, E, OT, FT, I, R>,
        C: Corpus<I, R>,
        E: Executor<I>,
        OT: ObserversTuple,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
        dbg!("TIMEOUT/SIGUSR2 received");
        if CURRENT_INPUT_PTR == ptr::null() {
            dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing.");
            return;
        }

        let input = (CURRENT_INPUT_PTR as *const I).as_ref().unwrap();
        let manager = (EVENT_MANAGER_PTR as *mut EM).as_mut().unwrap();

        manager
            .timeout(input)
            .expect("Error in sending Timeout event");

        // TODO: send LLMP.
        println!("Timeout in fuzz run.");
        let _ = stdout().flush();
        process::abort();
    }

    // TODO clearly state that manager should be static (maybe put the 'static lifetime?)
    pub unsafe fn setup_crash_handlers<EM, C, E, OT, FT, I, R>(manager: &mut EM)
    where
        EM: EventManager<C, E, OT, FT, I, R>,
        C: Corpus<I, R>,
        E: Executor<I>,
        OT: ObserversTuple,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
        EVENT_MANAGER_PTR = manager as *mut _ as *mut c_void;

        let mut sa: sigaction = mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        sa.sa_flags = SA_NODEFER | SA_SIGINFO;
        sa.sa_sigaction = libaflrs_executor_inmem_handle_crash::<EM, C, E, OT, FT, I, R> as usize;
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

        sa.sa_sigaction = libaflrs_executor_inmem_handle_timeout::<EM, C, E, OT, FT, I, R> as usize;
        if sigaction(SIGUSR2, &mut sa as *mut sigaction, ptr::null_mut()) < 0 {
            panic!("Could not set up sigusr2 handler for timeouts");
        }
    }
}

//#[cfg(feature = "std")]
//#[cfg(unix)]
//use unix_signals as os_signals;
//#[cfg(feature = "std")]
//#[cfg(not(unix))]
//compile_error!("InMemoryExecutor not yet supported on this OS");

#[cfg(test)]
mod tests {

    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::{HasTargetBytes, Input, TargetBytes};
    use crate::tuples::tuple_list;

    use serde::{Deserialize, Serialize};

    #[derive(Clone, Serialize, Deserialize, Debug)]
    struct NopInput {}
    impl Input for NopInput {}
    impl HasTargetBytes for NopInput {
        fn target_bytes(&self) -> TargetBytes {
            TargetBytes::Owned(vec![0])
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
        let mut in_mem_executor = InMemoryExecutor::new("main", test_harness_fn_nop, tuple_list!());
        let mut input = NopInput {};
        assert!(in_mem_executor.run_target(&mut input).is_ok());
    }
}
