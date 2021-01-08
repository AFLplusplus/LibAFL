use alloc::boxed::Box;
use core::{ffi::c_void, ptr};

use crate::{
    corpus::Corpus,
    engines::State,
    events::EventManager,
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::FeedbacksTuple,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    tuples::Named,
    utils::Rand,
    AflError,
};

#[cfg(feature = "std")]
#[cfg(unix)]
use unix_signals as os_signals;

#[cfg(feature = "std")]
use self::os_signals::setup_crash_handlers;

/// The (unsafe) pointer to the current inmem input, for the current run.
/// This is neede for certain non-rust side effects, as well as unix signal handling.
static mut CURRENT_INPUT_PTR: *const c_void = ptr::null();
static mut CURRENT_ON_CRASH_FN: *mut c_void = ptr::null_mut();

/// The inmem executor harness
type HarnessFunction<I> = fn(&dyn Executor<I>, &[u8]) -> ExitKind;
type OnCrashFunction<I, C, EM, FT, R> = dyn FnMut(ExitKind, &I, &State<I, R, FT>, &C, &mut EM);

/// The inmem executor simply calls a target function, then returns afterwards.
pub struct InMemoryExecutor<I, OT, C, EM, FT, R>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
    C: Corpus<I, R>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    R: Rand,
{
    /// The name of this executor instance, to address it from other components
    name: &'static str,
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: HarnessFunction<I>,
    /// The observers, observing each run
    observers: OT,
    /// A special function being called right before the process crashes. It may save state to restore fuzzing after respawn.
    on_crash_fn: Box<OnCrashFunction<I, C, EM, FT, R>>,
}

impl<I, OT, C, EM, FT, R> Executor<I> for InMemoryExecutor<I, OT, C, EM, FT, R>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
    C: Corpus<I, R>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    R: Rand,
{
    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, AflError> {
        let bytes = input.target_bytes();
        unsafe {
            CURRENT_ON_CRASH_FN = &mut self.on_crash_fn as *mut _ as *mut c_void;
            CURRENT_INPUT_PTR = input as *const _ as *const c_void;
        }
        let ret = (self.harness_fn)(self, bytes.as_slice());
        unsafe {
            CURRENT_ON_CRASH_FN = ptr::null_mut();
            CURRENT_INPUT_PTR = ptr::null();
        }
        Ok(ret)
    }
}

impl<I, OT, C, EM, FT, R> Named for InMemoryExecutor<I, OT, C, EM, FT, R>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
    C: Corpus<I, R>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    R: Rand,
{
    fn name(&self) -> &str {
        self.name
    }
}

impl<I, OT, C, EM, FT, R> HasObservers<OT> for InMemoryExecutor<I, OT, C, EM, FT, R>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
    C: Corpus<I, R>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    R: Rand,
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

impl<I, OT, C, EM, FT, R> InMemoryExecutor<I, OT, C, EM, FT, R>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
    C: Corpus<I, R>,
    EM: EventManager<I>,
    FT: FeedbacksTuple<I>,
    R: Rand,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depnding on different corpus or state.
    /// * `name` - the name of this executor (to address it along the way)
    /// * `harness_fn` - the harness, executiong the function
    /// * `on_crash_fn` - When an in-mem harness crashes, it may safe some state to continue fuzzing later.
    ///                   Do that that in this function. The program will crash afterwards.
    /// * `observers` - the observers observing the target during execution
    pub fn new(
        name: &'static str,
        harness_fn: HarnessFunction<I>,
        observers: OT,
        on_crash_fn: Box<OnCrashFunction<I, C, EM, FT, R>>,
        _state: &State<I, R, FT>,
        _corpus: &C,
        _event_mgr: &mut EM,
    ) -> Self {
        #[cfg(feature = "std")]
        unsafe {
            setup_crash_handlers::<EM, C, OT, FT, I, R>(_state, _corpus, _event_mgr);
        }

        Self {
            harness_fn,
            on_crash_fn,
            observers,
            name,
        }
    }
}

#[cfg(feature = "std")]
#[cfg(unix)]
pub mod unix_signals {

    extern crate libc;

    // Unhandled signals: SIGALRM, SIGHUP, SIGINT, SIGKILL, SIGQUIT, SIGTERM
    use libc::{
        c_int, c_void, sigaction, siginfo_t, SA_NODEFER, SA_SIGINFO, SIGABRT, SIGBUS, SIGFPE,
        SIGILL, SIGPIPE, SIGSEGV, SIGUSR2,
    };

    use std::{
        io::{stdout, Write}, // Write brings flush() into scope
        mem,
        process,
        ptr,
    };

    use crate::{
        corpus::Corpus,
        engines::State,
        events::EventManager,
        executors::inmemory::{ExitKind, OnCrashFunction, CURRENT_INPUT_PTR, CURRENT_ON_CRASH_FN},
        feedbacks::FeedbacksTuple,
        inputs::Input,
        observers::ObserversTuple,
        utils::Rand,
    };

    /// Pointers to values only needed on crash. As the program will not continue after a crash,
    /// we should (tm) be okay with raw pointers here,
    static mut CORPUS_PTR: *const c_void = ptr::null_mut();
    static mut STATE_PTR: *const c_void = ptr::null_mut();
    static mut EVENT_MANAGER_PTR: *mut c_void = ptr::null_mut();

    pub unsafe extern "C" fn libaflrs_executor_inmem_handle_crash<EM, C, OT, FT, I, R>(
        _sig: c_int,
        info: siginfo_t,
        _void: c_void,
    ) where
        EM: EventManager<I>,
        C: Corpus<I, R>,
        OT: ObserversTuple,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
        if CURRENT_INPUT_PTR == ptr::null() {
            println!(
                "We died accessing addr {}, but are not in client... Exiting.",
                info.si_addr() as usize
            );
            return;
        }

        #[cfg(feature = "std")]
        println!("Child crashed!");
        #[cfg(feature = "std")]
        let _ = stdout().flush();

        let input = (CURRENT_INPUT_PTR as *const I).as_ref().unwrap();
        let corpus = (CORPUS_PTR as *const C).as_ref().unwrap();
        let state = (EVENT_MANAGER_PTR as *const State<I, R, FT>)
            .as_ref()
            .unwrap();
        let manager = (EVENT_MANAGER_PTR as *mut EM).as_mut().unwrap();

        if !CURRENT_ON_CRASH_FN.is_null() {
            (*(CURRENT_ON_CRASH_FN as *mut Box<OnCrashFunction<I, C, EM, FT, R>>))(
                ExitKind::Crash,
                input,
                state,
                corpus,
                manager,
            );
        }

        std::process::exit(139);
    }

    pub unsafe extern "C" fn libaflrs_executor_inmem_handle_timeout<EM, C, OT, FT, I, R>(
        _sig: c_int,
        _info: siginfo_t,
        _void: c_void,
    ) where
        EM: EventManager<I>,
        C: Corpus<I, R>,
        OT: ObserversTuple,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
        dbg!("TIMEOUT/SIGUSR2 received");
        if CURRENT_INPUT_PTR.is_null() {
            dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing. Exiting");
            return;
        }

        let input = (CURRENT_INPUT_PTR as *const I).as_ref().unwrap();
        let corpus = (CORPUS_PTR as *const C).as_ref().unwrap();
        let state = (EVENT_MANAGER_PTR as *const State<I, R, FT>)
            .as_ref()
            .unwrap();
        let manager = (EVENT_MANAGER_PTR as *mut EM).as_mut().unwrap();

        if !CURRENT_ON_CRASH_FN.is_null() {
            (*(CURRENT_ON_CRASH_FN as *mut Box<OnCrashFunction<I, C, EM, FT, R>>))(
                ExitKind::Timeout,
                input,
                state,
                corpus,
                manager,
            );
        }

        // TODO: send LLMP.
        println!("Timeout in fuzz run.");
        let _ = stdout().flush();
        process::abort();
    }

    // TODO clearly state that manager should be static (maybe put the 'static lifetime?)
    pub unsafe fn setup_crash_handlers<EM, C, OT, FT, I, R>(
        state: &State<I, R, FT>,
        corpus: &C,
        manager: &mut EM,
    ) where
        EM: EventManager<I>,
        C: Corpus<I, R>,
        OT: ObserversTuple,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
        CORPUS_PTR = corpus as *const _ as *const c_void;
        STATE_PTR = state as *const _ as *const c_void;
        EVENT_MANAGER_PTR = manager as *mut _ as *mut c_void;

        let mut sa: sigaction = mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        sa.sa_flags = SA_NODEFER | SA_SIGINFO;
        sa.sa_sigaction = libaflrs_executor_inmem_handle_crash::<EM, C, OT, FT, I, R> as usize;
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

        sa.sa_sigaction = libaflrs_executor_inmem_handle_timeout::<EM, C, OT, FT, I, R> as usize;
        if sigaction(SIGUSR2, &mut sa as *mut sigaction, ptr::null_mut()) < 0 {
            panic!("Could not set up sigusr2 handler for timeouts");
        }
    }
}

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;

    use crate::{
        executors::{Executor, ExitKind, InMemoryExecutor},
        inputs::NopInput,
        tuples::tuple_list,
    };

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
        use crate::{
            corpus::InMemoryCorpus, events::NopEventManager, inputs::NopInput, utils::StdRand,
        };

        let mut in_mem_executor = InMemoryExecutor::<
            NopInput,
            (),
            InMemoryCorpus<_, _>,
            NopEventManager<_>,
            (),
            StdRand,
        > {
            harness_fn: test_harness_fn_nop,
            on_crash_fn: Box::new(|_, _, _, _, _| ()),
            observers: tuple_list!(),
            name: "main",
        };
        let mut input = NopInput {};
        assert!(in_mem_executor.run_target(&mut input).is_ok());
    }
}
