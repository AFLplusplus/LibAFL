//! The InProcess Executor is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.

use core::marker::PhantomData;
#[cfg(feature = "std")]
#[cfg(unix)]
use os_signals::set_oncrash_ptrs;

use crate::{
    bolts::tuples::Named,
    corpus::Corpus,
    events::EventManager,
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::FeedbacksTuple,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    state::{HasObjectives, HasSolutions},
    Error,
};

#[cfg(feature = "std")]
#[cfg(unix)]
use unix_signals as os_signals;

#[cfg(feature = "std")]
#[cfg(unix)]
use self::os_signals::reset_oncrash_ptrs;
#[cfg(feature = "std")]
#[cfg(unix)]
use self::os_signals::setup_crash_handlers;

/// The inmem executor harness
type HarnessFunction<E> = fn(&E, &[u8]) -> ExitKind;

/// The inmem executor simply calls a target function, then returns afterwards.
pub struct InProcessExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// The name of this executor instance, to address it from other components
    name: &'static str,
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: HarnessFunction<Self>,
    /// The observers, observing each run
    observers: OT,
    phantom: PhantomData<I>,
}

impl<I, OT> Executor<I> for InProcessExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn pre_exec<EM, S>(
        &mut self,
        _state: &mut S,
        _event_mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        #[cfg(unix)]
        #[cfg(feature = "std")]
        unsafe {
            set_oncrash_ptrs(_state, _event_mgr, self.observers(), _input);
        }
        Ok(())
    }

    #[inline]
    fn post_exec<EM, S>(&mut self, _state: &S, _event_mgr: &mut EM, _input: &I) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        #[cfg(unix)]
        #[cfg(feature = "std")]
        unsafe {
            reset_oncrash_ptrs();
        }
        Ok(())
    }

    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        let bytes = input.target_bytes();
        let ret = (self.harness_fn)(self, bytes.as_slice());
        Ok(ret)
    }
}

impl<I, OT> Named for InProcessExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        self.name
    }
}

impl<I, OT> HasObservers<OT> for InProcessExecutor<I, OT>
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

impl<I, OT> InProcessExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depnding on different corpus or state.
    /// * `name` - the name of this executor (to address it along the way)
    /// * `harness_fn` - the harness, executiong the function
    /// * `observers` - the observers observing the target during execution
    pub fn new<EM, OC, OFT, S>(
        name: &'static str,
        harness_fn: HarnessFunction<Self>,
        observers: OT,
        _state: &mut S,
        _event_mgr: &mut EM,
    ) -> Self
    where
        EM: EventManager<I, S>,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
    {
        #[cfg(feature = "std")]
        #[cfg(unix)]
        unsafe {
            setup_crash_handlers::<EM, I, OC, OFT, OT, S>();
        }

        Self {
            harness_fn,
            observers,
            name,
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "std")]
#[cfg(unix)]
pub mod unix_signals {

    extern crate libc;

    // Unhandled signals: SIGALRM, SIGHUP, SIGINT, SIGKILL, SIGQUIT, SIGTERM
    use libc::{
        c_int, c_void, malloc, sigaction, sigaltstack, siginfo_t, SA_NODEFER, SA_ONSTACK,
        SA_SIGINFO, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGPIPE, SIGSEGV, SIGUSR2,
    };

    use std::{
        fs,
        io::{stdout, Write},
        mem, ptr,
    };

    use crate::{
        corpus::{Corpus, Testcase},
        events::{Event, EventManager},
        executors::ExitKind,
        feedbacks::FeedbacksTuple,
        inputs::Input,
        observers::ObserversTuple,
        state::{HasObjectives, HasSolutions},
    };
    /// Let's get 8 mb for now.
    const SIGNAL_STACK_SIZE: usize = 2 << 22;
    /// To be able to handle SIGSEGV when the stack is exhausted, we need our own little stack space.
    static mut SIGNAL_STACK_PTR: *const c_void = ptr::null_mut();

    /// Pointers to values only needed on crash. As the program will not continue after a crash,
    /// we should (tm) be okay with raw pointers here,
    static mut STATE_PTR: *mut c_void = ptr::null_mut();
    static mut EVENT_MGR_PTR: *mut c_void = ptr::null_mut();
    static mut OBSERVERS_PTR: *const c_void = ptr::null();
    /// The (unsafe) pointer to the current inmem input, for the current run.
    /// This is needed for certain non-rust side effects, as well as unix signal handling.
    static mut CURRENT_INPUT_PTR: *const c_void = ptr::null();

    unsafe fn inmem_handle_crash<EM, I, OC, OFT, OT, S>(_sig: c_int, info: siginfo_t, _void: c_void)
    where
        EM: EventManager<I, S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
        I: Input,
    {
        if CURRENT_INPUT_PTR == ptr::null() {
            #[cfg(target_os = "android")]
            let si_addr = { ((info._pad[0] as usize) | ((info._pad[1] as usize) << 32)) as usize };
            #[cfg(not(target_os = "android"))]
            let si_addr = { info.si_addr() as usize };

            println!(
                "We crashed at addr 0x{:x}, but are not in the target... Bug in the fuzzer? Exiting.",
                si_addr
            );
            // let's yolo-cat the maps for debugging, if possible.
            #[cfg(target_os = "linux")]
            match fs::read_to_string("/proc/self/maps") {
                Ok(maps) => println!("maps:\n{}", maps),
                Err(e) => println!("Couldn't load mappings: {:?}", e),
            };
            #[cfg(feature = "std")]
            {
                println!("Type QUIT to restart the child");
                let mut line = String::new();
                while line.trim() != "QUIT" {
                    std::io::stdin().read_line(&mut line).unwrap();
                }
            }

            // TODO tell the parent to not restart
            std::process::exit(1);
        }

        #[cfg(feature = "std")]
        println!("Child crashed!");
        #[cfg(feature = "std")]
        let _ = stdout().flush();

        let input = (CURRENT_INPUT_PTR as *const I).as_ref().unwrap();
        // Make sure we don't crash in the crash handler forever.
        CURRENT_INPUT_PTR = ptr::null();
        let state = (STATE_PTR as *mut S).as_mut().unwrap();
        let mgr = (EVENT_MGR_PTR as *mut EM).as_mut().unwrap();

        let observers = (OBSERVERS_PTR as *const OT).as_ref().unwrap();
        let obj_fitness = state
            .objectives_mut()
            .is_interesting_all(&input, observers, ExitKind::Crash)
            .expect("In crash handler objectives failure.".into());
        if obj_fitness > 0 {
            state
                .solutions_mut()
                .add(Testcase::new(input.clone()))
                .expect("In crash handler solutions failure.".into());
            mgr.fire(
                state,
                Event::Objective {
                    objective_size: state.solutions().count(),
                },
            )
            .expect("Could not send crashing input".into());
        }

        mgr.on_restart(state).unwrap();

        println!("Waiting for broker...");
        mgr.await_restart_safe();
        println!("Bye!");

        std::process::exit(1);
    }

    unsafe fn inmem_handle_timeout<EM, I, OC, OFT, OT, S>(
        _sig: c_int,
        _info: siginfo_t,
        _void: c_void,
    ) where
        EM: EventManager<I, S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
        I: Input,
    {
        dbg!("TIMEOUT/SIGUSR2 received");
        if CURRENT_INPUT_PTR.is_null() {
            dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing. Exiting");
            return;
        }

        println!("Timeout in fuzz run.");
        let _ = stdout().flush();

        let input = (CURRENT_INPUT_PTR as *const I).as_ref().unwrap();
        // Make sure we don't crash in the crash handler forever.
        CURRENT_INPUT_PTR = ptr::null();
        let state = (STATE_PTR as *mut S).as_mut().unwrap();
        let mgr = (EVENT_MGR_PTR as *mut EM).as_mut().unwrap();

        let observers = (OBSERVERS_PTR as *const OT).as_ref().unwrap();
        let obj_fitness = state
            .objectives_mut()
            .is_interesting_all(&input, observers, ExitKind::Crash)
            .expect("In timeout handler objectives failure.".into());
        if obj_fitness > 0 {
            state
                .solutions_mut()
                .add(Testcase::new(input.clone()))
                .expect("In timeout handler solutions failure.".into());
            mgr.fire(
                state,
                Event::Objective {
                    objective_size: state.solutions().count(),
                },
            )
            .expect("Could not send timeouting input".into());
        }

        mgr.on_restart(state).unwrap();

        println!("Waiting for broker...");
        mgr.await_restart_safe();
        println!("Bye!");

        mgr.await_restart_safe();

        std::process::exit(1);
    }

    #[inline]
    pub unsafe fn set_oncrash_ptrs<EM, I, OT, S>(
        state: &mut S,
        event_mgr: &mut EM,
        observers: &OT,
        input: &I,
    ) {
        CURRENT_INPUT_PTR = input as *const _ as *const c_void;
        STATE_PTR = state as *mut _ as *mut c_void;
        EVENT_MGR_PTR = event_mgr as *mut _ as *mut c_void;
        OBSERVERS_PTR = observers as *const _ as *const c_void;
    }

    #[inline]
    pub unsafe fn reset_oncrash_ptrs() {
        CURRENT_INPUT_PTR = ptr::null();
        STATE_PTR = ptr::null_mut();
        EVENT_MGR_PTR = ptr::null_mut();
        OBSERVERS_PTR = ptr::null();
    }

    pub unsafe fn setup_crash_handlers<EM, I, OC, OFT, OT, S>()
    where
        EM: EventManager<I, S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
        I: Input,
    {
        // First, set up our own stack to be used during segfault handling. (and specify `SA_ONSTACK` in `sigaction`)
        if SIGNAL_STACK_PTR.is_null() {
            SIGNAL_STACK_PTR = malloc(SIGNAL_STACK_SIZE);
            if SIGNAL_STACK_PTR.is_null() {
                panic!(
                    "Failed to allocate signal stack with {} bytes!",
                    SIGNAL_STACK_SIZE
                );
            }
        }
        sigaltstack(SIGNAL_STACK_PTR as _, ptr::null_mut() as _);

        let mut sa: sigaction = mem::zeroed();
        libc::sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
        sa.sa_flags = SA_NODEFER | SA_SIGINFO | SA_ONSTACK;
        sa.sa_sigaction = inmem_handle_crash::<EM, I, OC, OFT, OT, S> as usize;
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

        sa.sa_sigaction = inmem_handle_timeout::<EM, I, OC, OFT, OT, S> as usize;
        if sigaction(SIGUSR2, &mut sa as *mut sigaction, ptr::null_mut()) < 0 {
            panic!("Could not set up sigusr2 handler for timeouts");
        }
    }
}

#[cfg(test)]
mod tests {

    use core::marker::PhantomData;

    use crate::{
        bolts::tuples::tuple_list,
        executors::{Executor, ExitKind, InProcessExecutor},
        inputs::Input,
    };

    fn test_harness_fn_nop<E: Executor<I>, I: Input>(_executor: &E, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_inmem_exec() {
        use crate::inputs::NopInput;

        let mut in_process_executor = InProcessExecutor::<NopInput, ()> {
            harness_fn: test_harness_fn_nop,
            // TODO: on_crash_fn: Box::new(|_, _, _, _, _| ()),
            observers: tuple_list!(),
            name: "main",
            phantom: PhantomData,
        };
        let mut input = NopInput {};
        assert!(in_process_executor.run_target(&mut input).is_ok());
    }
}
