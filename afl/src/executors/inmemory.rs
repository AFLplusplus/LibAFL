use alloc::boxed::Box;
use core::{ffi::c_void, ptr};
use os_signals::set_oncrash_ptrs;

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

use self::os_signals::reset_oncrash_ptrs;
#[cfg(feature = "std")]
use self::os_signals::setup_crash_handlers;

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
    fn run_target(
        &mut self,
        input: &I,
        state: State<I, R, FT>,
        corpus: &C,
        event_mgr: &EM,
    ) -> Result<ExitKind, AflError> {
        #[cfg(unix)]
        unsafe {
            set_oncrash_ptrs::<EM, C, OT, FT, I, R>(
                state,
                corpus,
                event_mgr,
                input,
                &mut self.on_crash_fn,
            );
        }
        let bytes = input.target_bytes();
        let ret = (self.harness_fn)(self, bytes.as_slice());
        #[cfg(unix)]
        unsafe {
            reset_oncrash_ptrs::<EM, C, OT, FT, I, R>();
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
            setup_crash_handlers::<EM, C, OT, FT, I, R>();
        }

        Self {
            harness_fn,
            on_crash_fn,
            observers,
            name,
        }
    }
}

/*
unsafe fn tidy_up_on_exit<EM>(mgr: &EM)
where
EM: EventManager<I>,
I: Input,
{

            match manager.llmp {
            IsClient { client } => {
                let map = client.out_maps.last().unwrap();
                /// wait until we can drop the message safely.
                map.await_save_to_unmap_blocking();
                /// Make sure all pages are unmapped.
                drop(manager);
            }
            _ => (),
        }
}*/

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
        executors::inmemory::{ExitKind, OnCrashFunction},
        feedbacks::FeedbacksTuple,
        inputs::Input,
        observers::ObserversTuple,
        utils::Rand,
    };

    /// Pointers to values only needed on crash. As the program will not continue after a crash,
    /// we should (tm) be okay with raw pointers here,
    static mut corpus_ptr: *const c_void = ptr::null_mut();
    static mut state_ptr: *const c_void = ptr::null_mut();
    static mut event_mgr_ptr: *mut c_void = ptr::null_mut();
    /// The (unsafe) pointer to the current inmem input, for the current run.
    /// This is neede for certain non-rust side effects, as well as unix signal handling.
    static mut current_input_ptr: *const c_void = ptr::null();
    static mut on_crash_fn_ptr: *mut c_void = ptr::null_mut();

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
        if current_input_ptr == ptr::null() {
            println!(
                "We died accessing addr {}, but are not in client... Exiting.",
                info.si_addr() as usize
            );
            return;
            //exit(1);
        }

        #[cfg(feature = "std")]
        println!("Child crashed!");
        #[cfg(feature = "std")]
        let _ = stdout().flush();

        let input = (current_input_ptr as *const I).as_ref().unwrap();
        let corpus = (corpus_ptr as *const C).as_ref().unwrap();
        let state = (event_mgr_ptr as *const State<I, R, FT>).as_ref().unwrap();
        let manager = (event_mgr_ptr as *mut EM).as_mut().unwrap();

        if !on_crash_fn_ptr.is_null() {
            (*(on_crash_fn_ptr as *mut Box<OnCrashFunction<I, C, EM, FT, R>>))(
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
        if current_input_ptr.is_null() {
            dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing. Exiting");
            return;
        }

        let input = (current_input_ptr as *const I).as_ref().unwrap();
        let corpus = (corpus_ptr as *const C).as_ref().unwrap();
        let state = (event_mgr_ptr as *const State<I, R, FT>).as_ref().unwrap();
        let manager = (event_mgr_ptr as *mut EM).as_mut().unwrap();

        if !on_crash_fn_ptr.is_null() {
            (*(on_crash_fn_ptr as *mut Box<OnCrashFunction<I, C, EM, FT, R>>))(
                ExitKind::Timeout,
                input,
                state,
                corpus,
                manager,
            );
        }

        /* TODO: If we want to be on the safe side, we really need to do this:
        match manager.llmp {
            IsClient { client } => {
                let map = client.out_maps.last().unwrap();
                /// wait until we can drop the message safely.
                map.await_save_to_unmap_blocking();
                /// Make sure all pages are unmapped.
                drop(manager);
            }
            _ => (),
        }
        */

        println!("Timeout in fuzz run.");
        let _ = stdout().flush();
        process::abort();
    }

    #[inline]
    pub unsafe fn set_oncrash_ptrs<EM, C, OT, FT, I, R>(
        state: &State<I, R, FT>,
        corpus: &C,
        event_mgr: &mut EM,
        input: I,
        on_crash_handler: &mut Box<OnCrashFunction<I, C, EM, FT, R>>,
    ) where
        EM: EventManager<I>,
        C: Corpus<I, R>,
        OT: ObserversTuple,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
        current_input_ptr = input as *const _ as *const c_void;
        corpus_ptr = corpus as *const _ as *const c_void;
        state_ptr = state as *const _ as *const c_void;
        event_mgr_ptr = event_mgr as *mut _ as *mut c_void;
        on_crash_fn_ptr = on_crash_handler as *mut _ as *mut c_void;
    }

    #[inline]
    pub unsafe fn reset_oncrash_ptrs<EM, C, OT, FT, I, R>() {
        current_input_ptr = ptr::null();
        corpus_ptr = ptr::null();
        state_ptr = ptr::null();
        event_mgr_ptr = ptr::null_mut();
        on_crash_fn_ptr = ptr::null_mut();
    }

    // TODO clearly state that manager should be static (maybe put the 'static lifetime?)
    pub unsafe fn setup_crash_handlers<EM, C, OT, FT, I, R>()
    where
        EM: EventManager<I>,
        C: Corpus<I, R>,
        OT: ObserversTuple,
        FT: FeedbacksTuple<I>,
        I: Input,
        R: Rand,
    {
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
