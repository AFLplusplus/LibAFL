//! The [`InProcessExecutor`] is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.
//!
//! Needs the `fork` feature flag.

use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr,
};

#[cfg(any(unix, all(windows, feature = "std")))]
use core::{
    ptr::write_volatile,
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(feature = "std")]
use std::intrinsics::transmute;

#[cfg(all(feature = "std", unix))]
use libc::{siginfo_t, ucontext_t};

#[cfg(all(feature = "std", unix))]
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::{fork, ForkResult},
};

#[cfg(all(feature = "std", windows))]
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;

#[cfg(unix)]
use crate::bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(windows, feature = "std"))]
use crate::bolts::os::windows_exceptions::setup_exception_handler;
#[cfg(all(feature = "std", unix))]
use crate::bolts::shmem::ShMemProvider;
#[cfg(feature = "std")]
use crate::observers::{BacktraceObserver, HarnessType};

#[cfg(windows)]
use windows::Win32::System::Threading::SetThreadStackGuarantee;

#[cfg(all(feature = "std", windows))]
use crate::bolts::os::windows_exceptions::{ExceptionCode, Handler, CRASH_EXCEPTIONS};

use crate::{
    events::{EventFirer, EventRestarter},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasSolutions},
    Error,
};

#[cfg(feature = "std")]
use crate::executors::inprocess::bt_signal_handlers::setup_bt_panic_hook;
#[cfg(all(feature = "std", unix))]
use crate::{
    bolts::os::unix_signals::{Handler, Signal},
    executors::inprocess::bt_signal_handlers::setup_child_panic_hook,
};

/// The inmem executor simply calls a target function, then returns afterwards.
#[allow(dead_code)]
pub struct InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: &'a mut H,
    /// The observers, observing each run
    observers: OT,
    // Crash and timeout hah
    handlers: InProcessHandlers,
    phantom: PhantomData<(I, S)>,
}

impl<'a, H, I, OT, S> Debug for InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessExecutor")
            .field("harness_fn", &"<fn>")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl<'a, EM, H, I, OT, S, Z> Executor<EM, I, S, Z> for InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.handlers
            .pre_run_target(self, fuzzer, state, mgr, input);

        let ret = (self.harness_fn)(input);

        self.handlers.post_run_target();
        Ok(ret)
    }
}

impl<'a, H, I, OT, S> HasObservers<I, OT, S> for InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
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

impl<'a, H, I, OT, S> InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `harness_fn` - the harness, executiong the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<I> + EventRestarter<S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        Z: HasObjective<I, OF, S>,
    {
        #[cfg(feature = "std")]
        BacktraceObserver::setup_static_variable();

        #[cfg(feature = "std")]
        if let Some(obs) = observers.match_name::<BacktraceObserver>("BacktraceObserver") {
            if obs.harness_type() == &HarnessType::RUST {
                setup_bt_panic_hook::<
                    InProcessExecutor<H, I, OT, S>,
                    I,
                    OT,
                    S,
                    InProcessExecutorHandlerData,
                >(unsafe { &GLOBAL_STATE });
            }
        }
        let handlers = InProcessHandlers::new::<Self, EM, I, OF, OT, S, Z, H>()?;
        #[cfg(windows)]
        unsafe {
            /*
                See https://github.com/AFLplusplus/LibAFL/pull/403
                This one reserves certain amount of memory for the stack.
                If stack overflow happens during fuzzing on windows, the program is transferred to our exception handler for windows.
                However, if we run out of the stack memory again in this exception handler, we'll crash with STATUS_ACCESS_VIOLATION.
                We need this API call because with the llmp_compression
                feature enabled, the exception handler uses a lot of stack memory (in the compression lib code) on release build.
                As far as I have observed, the compression uses around 0x10000 bytes, but for safety let's just reserve 0x20000 bytes for our exception handlers.
                This number 0x20000 could vary depending on the compilers optimization for future compression library changes.
            */
            let mut stack_reserved = 0x20000;
            SetThreadStackGuarantee(&mut stack_reserved);
        }
        Ok(Self {
            harness_fn,
            observers,
            handlers,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness_fn
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn
    }

    /// The inprocess handlers
    #[inline]
    pub fn handlers(&self) -> &InProcessHandlers {
        &self.handlers
    }

    /// The inprocess handlers, mut
    #[inline]
    pub fn handlers_mut(&mut self) -> &mut InProcessHandlers {
        &mut self.handlers
    }
}

/// The inmem executor's handlers.
#[derive(Debug)]
pub struct InProcessHandlers {
    /// On crash C function pointer
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    pub timeout_handler: *const c_void,
}

impl InProcessHandlers {
    /// Call before running a target.
    #[allow(clippy::unused_self)]
    pub fn pre_run_target<E, EM, I, S, Z>(
        &self,
        _executor: &E,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
        #[cfg(unix)]
        unsafe {
            let data = &mut GLOBAL_STATE;
            write_volatile(
                &mut data.current_input_ptr,
                _input as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.executor_ptr,
                _executor as *const _ as *const c_void,
            );
            data.crash_handler = self.crash_handler;
            data.timeout_handler = self.timeout_handler;
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(&mut data.state_ptr, _state as *mut _ as *mut c_void);
            write_volatile(&mut data.event_mgr_ptr, _mgr as *mut _ as *mut c_void);
            write_volatile(&mut data.fuzzer_ptr, _fuzzer as *mut _ as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(all(windows, feature = "std"))]
        unsafe {
            let data = &mut GLOBAL_STATE;
            write_volatile(
                &mut data.current_input_ptr,
                _input as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.executor_ptr,
                _executor as *const _ as *const c_void,
            );
            data.crash_handler = self.crash_handler;
            data.timeout_handler = self.timeout_handler;
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(&mut data.state_ptr, _state as *mut _ as *mut c_void);
            write_volatile(&mut data.event_mgr_ptr, _mgr as *mut _ as *mut c_void);
            write_volatile(&mut data.fuzzer_ptr, _fuzzer as *mut _ as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Call after running a target.
    #[allow(clippy::unused_self)]
    pub fn post_run_target(&self) {
        #[cfg(unix)]
        unsafe {
            write_volatile(&mut GLOBAL_STATE.current_input_ptr, ptr::null());
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(all(windows, feature = "std"))]
        unsafe {
            write_volatile(&mut GLOBAL_STATE.current_input_ptr, ptr::null());
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Create new [`InProcessHandlers`].
    pub fn new<E, EM, I, OF, OT, S, Z, H>() -> Result<Self, Error>
    where
        I: Input,
        E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
        OT: ObserversTuple<I, S>,
        EM: EventFirer<I> + EventRestarter<S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        Z: HasObjective<I, OF, S>,
        H: FnMut(&I) -> ExitKind,
    {
        #[cfg(unix)]
        unsafe {
            let data = &mut GLOBAL_STATE;
            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                crash_handler: unix_signal_handler::inproc_crash_handler::<E, EM, I, OF, OT, S, Z>
                    as *const c_void,
                timeout_handler: unix_signal_handler::inproc_timeout_handler::<E, EM, I, OF, OT, S, Z>
                    as *const _,
            })
        }
        #[cfg(all(windows, feature = "std"))]
        unsafe {
            let data = &mut GLOBAL_STATE;
            setup_exception_handler(data)?;
            compiler_fence(Ordering::SeqCst);

            Ok(Self {
                crash_handler: windows_exception_handler::inproc_crash_handler::<
                    E,
                    EM,
                    I,
                    OF,
                    OT,
                    S,
                    Z,
                > as *const _,
                timeout_handler: windows_exception_handler::inproc_timeout_handler::<
                    E,
                    EM,
                    I,
                    OF,
                    OT,
                    S,
                    Z,
                > as *const c_void,
            })
        }
        #[cfg(not(any(unix, all(windows, feature = "std"))))]
        Ok(Self {
            crash_handler: ptr::null(),
            timeout_handler: ptr::null(),
        })
    }

    /// Replace the handlers with `nop` handlers, deactivating the handlers
    #[must_use]
    pub fn nop() -> Self {
        Self {
            crash_handler: ptr::null(),
            timeout_handler: ptr::null(),
        }
    }
}
/// trait implemented by the static variables handling the global data
pub trait HasHandlerData: 'static + Sync {
    /// get executor
    fn executor<E>(&self) -> &E;
    /// get mutable executor
    #[allow(clippy::mut_from_ref)]
    fn executor_mut<E>(&self) -> &mut E;
    /// get state
    fn state<S>(&self) -> &S;
    /// get mutable state
    #[allow(clippy::mut_from_ref)]
    fn state_mut<S>(&self) -> &mut S;
    /// get current input
    fn current_input<I>(&self) -> &I;
    /// Check if the pointers in the handler are valid
    fn is_valid(&self) -> bool;
}
/// The global state of the in-process harness.
#[derive(Debug)]
#[allow(missing_docs)]
pub struct InProcessExecutorHandlerData {
    pub state_ptr: *mut c_void,
    pub event_mgr_ptr: *mut c_void,
    pub fuzzer_ptr: *mut c_void,
    pub executor_ptr: *const c_void,
    pub current_input_ptr: *const c_void,
    pub crash_handler: *const c_void,
    pub timeout_handler: *const c_void,
    #[cfg(windows)]
    pub tp_timer: *mut c_void,
    #[cfg(windows)]
    pub in_target: u64,
    #[cfg(windows)]
    pub critical: *mut c_void,
    #[cfg(windows)]
    pub timeout_input_ptr: *mut c_void,
}

unsafe impl Send for InProcessExecutorHandlerData {}
unsafe impl Sync for InProcessExecutorHandlerData {}

impl HasHandlerData for InProcessExecutorHandlerData {
    fn executor<E>(&self) -> &E {
        unsafe { (self.executor_ptr as *const E).as_ref().unwrap() }
    }

    fn executor_mut<E>(&self) -> &mut E {
        unsafe { (self.executor_ptr as *mut E).as_mut().unwrap() }
    }

    fn state<S>(&self) -> &S {
        unsafe { (self.state_ptr as *const S).as_ref().unwrap() }
    }

    fn state_mut<S>(&self) -> &mut S {
        unsafe { (self.state_ptr as *mut S).as_mut().unwrap() }
    }

    fn current_input<I>(&self) -> &I {
        unsafe { (self.current_input_ptr as *const I).as_ref().unwrap() }
    }

    #[cfg(windows)]
    fn is_valid(&self) -> bool {
        self.in_target == 1
    }

    #[cfg(not(windows))]
    fn is_valid(&self) -> bool {
        !self.current_input_ptr.is_null()
    }
}
/// Exception handling needs some nasty unsafe.
pub static mut GLOBAL_STATE: InProcessExecutorHandlerData = InProcessExecutorHandlerData {
    /// The state ptr for signal handling
    state_ptr: ptr::null_mut(),
    /// The event manager ptr for signal handling
    event_mgr_ptr: ptr::null_mut(),
    /// The fuzzer ptr for signal handling
    fuzzer_ptr: ptr::null_mut(),
    /// The executor ptr for signal handling
    executor_ptr: ptr::null(),
    /// The current input for signal handling
    current_input_ptr: ptr::null(),
    /// The crash handler fn
    crash_handler: ptr::null(),
    /// The timeout handler fn
    timeout_handler: ptr::null(),
    #[cfg(windows)]
    tp_timer: ptr::null_mut(),
    #[cfg(windows)]
    in_target: 0,
    #[cfg(windows)]
    critical: ptr::null_mut(),
    #[cfg(windows)]
    timeout_input_ptr: ptr::null_mut(),
};

/// Get the inprocess [`crate::state::State`]
#[must_use]
pub fn inprocess_get_state<'a, S>() -> Option<&'a mut S> {
    unsafe { (GLOBAL_STATE.state_ptr as *mut S).as_mut() }
}

/// Get the [`crate::events::EventManager`]
#[must_use]
pub fn inprocess_get_event_manager<'a, EM>() -> Option<&'a mut EM> {
    unsafe { (GLOBAL_STATE.event_mgr_ptr as *mut EM).as_mut() }
}

/// Gets the inprocess [`crate::fuzzer::Fuzzer`]
#[must_use]
pub fn inprocess_get_fuzzer<'a, F>() -> Option<&'a mut F> {
    unsafe { (GLOBAL_STATE.fuzzer_ptr as *mut F).as_mut() }
}

/// Gets the inprocess [`Executor`]
#[must_use]
pub fn inprocess_get_executor<'a, E>() -> Option<&'a mut E> {
    unsafe { (GLOBAL_STATE.executor_ptr as *mut E).as_mut() }
}

/// signal handlers and `panic_hooks` for used BT collection
#[cfg(feature = "std")]
pub mod bt_signal_handlers {

    use std::panic;

    #[cfg(all(unix))]
    use libc::{siginfo_t, ucontext_t};

    #[cfg(all(unix))]
    use crate::bolts::os::unix_signals::Signal;

    #[cfg(all(windows))]
    use windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;

    #[cfg(all(windows))]
    use super::InProcessExecutorHandlerData;

    use crate::{
        executors::{ExitKind, HasObservers},
        inputs::Input,
        observers::ObserversTuple,
        state::{HasClientPerfMonitor, HasSolutions},
    };

    use super::HasHandlerData;

    /// invokes the `post_exec` hook on all observer in case of panic
    pub fn setup_bt_panic_hook<E, I, OT, S, D>(data: &'static D)
    where
        E: HasObservers<I, OT, S>,
        OT: ObserversTuple<I, S>,
        I: Input,
        D: HasHandlerData,
    {
        let old_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            if data.is_valid() {
                let executor = data.executor_mut::<E>();
                let observers = executor.observers_mut();
                let state = data.state_mut::<S>();
                let input = data.current_input::<I>();
                observers
                    .post_exec_all(state, input, &ExitKind::Crash)
                    .expect("Failed to run post_exec on observers");
            }
            old_hook(panic_info);
        }));
    }

    /// invokes the `post_exec_child` hook on all observer in case the child process panics
    pub fn setup_child_panic_hook<E, I, OT, S, D>(data: &'static D)
    where
        E: HasObservers<I, OT, S>,
        OT: ObserversTuple<I, S>,
        I: Input,
        D: HasHandlerData,
    {
        let old_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            if data.is_valid() {
                let executor = data.executor_mut::<E>();
                let observers = executor.observers_mut();
                let state = data.state_mut::<S>();
                let input = data.current_input::<I>();
                observers
                    .post_exec_child_all(state, input, &ExitKind::Crash)
                    .expect("Failed to run post_exec on observers");
            }
            old_hook(panic_info);
        }));
    }

    /// invokes the `post_exec` hook on all observer in case the child process crashes
    #[cfg(unix)]
    pub fn child_crash_handler<E, I, OT, S, D>(
        _signal: Signal,
        _info: siginfo_t,
        _context: &mut ucontext_t,
        data: &D,
    ) where
        E: HasObservers<I, OT, S>,
        OT: ObserversTuple<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        I: Input,
        D: HasHandlerData,
    {
        if data.is_valid() {
            // redundant check, but better to be safe
            let executor = data.executor_mut::<E>();
            let observers = executor.observers_mut();
            let state = data.state_mut::<S>();
            let input = data.current_input::<I>();
            observers
                .post_exec_child_all(state, input, &ExitKind::Crash)
                .expect("Failed to run post_exec on observers");
        }
    }

    /// invokes the `post_exec` hook on all observer in case the child process crashes
    #[cfg(windows)]
    pub fn child_crash_handler<E, I, OT, S, D>(
        _exception_pointers: *mut EXCEPTION_POINTERS,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: HasObservers<I, OT, S>,
        OT: ObserversTuple<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        I: Input,
        D: HasHandlerData,
    {
        if data.is_valid() {
            // redundant check, but better to be safe
            let executor = data.executor_mut::<E>();
            let observers = executor.observers_mut();
            let state = data.state_mut::<S>();
            let input = data.current_input::<I>();
            observers
                .post_exec_child_all(state, input, &ExitKind::Crash)
                .expect("Failed to run post_exec on observers");
        }
    }
}

#[cfg(unix)]
mod unix_signal_handler {
    use alloc::vec::Vec;
    use core::{mem::transmute, ptr};
    use libc::siginfo_t;
    #[cfg(feature = "std")]
    use std::io::{stdout, Write};

    use crate::{
        bolts::os::unix_signals::{ucontext_t, Handler, Signal},
        corpus::{Corpus, Testcase},
        events::{Event, EventFirer, EventRestarter},
        executors::{
            inprocess::{InProcessExecutorHandlerData, GLOBAL_STATE},
            Executor, ExitKind, HasObservers,
        },
        feedbacks::Feedback,
        fuzzer::HasObjective,
        inputs::Input,
        observers::ObserversTuple,
        state::{HasClientPerfMonitor, HasMetadata, HasSolutions},
    };

    pub type HandlerFuncPtr =
        unsafe fn(Signal, siginfo_t, &mut ucontext_t, data: &mut InProcessExecutorHandlerData);

    /// A handler that does nothing.
    /*pub fn nop_handler(
        _signal: Signal,
        _info: siginfo_t,
        _context: &mut ucontext_t,
        _data: &mut InProcessExecutorHandlerData,
    ) {
    }*/

    #[cfg(unix)]
    impl Handler for InProcessExecutorHandlerData {
        fn handle(&mut self, signal: Signal, info: siginfo_t, context: &mut ucontext_t) {
            unsafe {
                let data = &mut GLOBAL_STATE;
                match signal {
                    Signal::SigUser2 | Signal::SigAlarm => {
                        if !data.timeout_handler.is_null() {
                            let func: HandlerFuncPtr = transmute(data.timeout_handler);
                            (func)(signal, info, context, data);
                        }
                    }
                    _ => {
                        if !data.crash_handler.is_null() {
                            let func: HandlerFuncPtr = transmute(data.crash_handler);
                            (func)(signal, info, context, data);
                        }
                    }
                }
            }
        }

        fn signals(&self) -> Vec<Signal> {
            vec![
                Signal::SigAlarm,
                Signal::SigUser2,
                Signal::SigAbort,
                Signal::SigBus,
                Signal::SigPipe,
                Signal::SigFloatingPointException,
                Signal::SigIllegalInstruction,
                Signal::SigSegmentationFault,
                Signal::SigTrap,
            ]
        }
    }

    #[cfg(unix)]
    pub unsafe fn inproc_timeout_handler<E, EM, I, OF, OT, S, Z>(
        _signal: Signal,
        _info: siginfo_t,
        _context: &mut ucontext_t,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: HasObservers<I, OT, S>,
        EM: EventFirer<I> + EventRestarter<S>,
        OT: ObserversTuple<I, S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        I: Input,
        Z: HasObjective<I, OF, S>,
    {
        let state = (data.state_ptr as *mut S).as_mut().unwrap();
        let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
        let fuzzer = (data.fuzzer_ptr as *mut Z).as_mut().unwrap();
        let executor = (data.executor_ptr as *mut E).as_mut().unwrap();
        let observers = executor.observers_mut();

        if data.current_input_ptr.is_null() {
            #[cfg(feature = "std")]
            println!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing.");
            return;
        }

        #[cfg(feature = "std")]
        println!("Timeout in fuzz run.");
        #[cfg(feature = "std")]
        let _res = stdout().flush();

        let input = (data.current_input_ptr as *const I).as_ref().unwrap();
        data.current_input_ptr = ptr::null();

        observers
            .post_exec_all(state, input, &ExitKind::Timeout)
            .expect("Observers post_exec_all failed");

        let interesting = fuzzer
            .objective_mut()
            .is_interesting(state, event_mgr, input, observers, &ExitKind::Timeout)
            .expect("In timeout handler objective failure.");

        if interesting {
            let mut new_testcase = Testcase::new(input.clone());
            new_testcase.add_metadata(ExitKind::Timeout);
            fuzzer
                .objective_mut()
                .append_metadata(state, &mut new_testcase)
                .expect("Failed adding metadata");
            state
                .solutions_mut()
                .add(new_testcase)
                .expect("In timeout handler solutions failure.");
            event_mgr
                .fire(
                    state,
                    Event::Objective {
                        objective_size: state.solutions().count(),
                    },
                )
                .expect("Could not send timeouting input");
        }

        event_mgr.on_restart(state).unwrap();

        #[cfg(feature = "std")]
        println!("Waiting for broker...");
        event_mgr.await_restart_safe();
        #[cfg(feature = "std")]
        println!("Bye!");

        event_mgr.await_restart_safe();

        libc::_exit(55);
    }

    /// Crash-Handler for in-process fuzzing.
    /// Will be used for signal handling.
    /// It will store the current State to shmem, then exit.
    #[allow(clippy::too_many_lines)]
    pub unsafe fn inproc_crash_handler<E, EM, I, OF, OT, S, Z>(
        signal: Signal,
        _info: siginfo_t,
        _context: &mut ucontext_t,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
        EM: EventFirer<I> + EventRestarter<S>,
        OT: ObserversTuple<I, S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        I: Input,
        Z: HasObjective<I, OF, S>,
    {
        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        let _context = &mut *(((_context as *mut _ as *mut libc::c_void as usize) + 128)
            as *mut libc::c_void as *mut ucontext_t);

        #[cfg(feature = "std")]
        eprintln!("Crashed with {}", signal);
        if data.current_input_ptr.is_null() {
            #[cfg(feature = "std")]
            {
                eprintln!("Double crash\n");
                #[cfg(target_os = "android")]
                let si_addr = (_info._pad[0] as i64) | ((_info._pad[1] as i64) << 32);
                #[cfg(not(target_os = "android"))]
                let si_addr = { _info.si_addr() as usize };

                eprintln!(
                "We crashed at addr 0x{:x}, but are not in the target... Bug in the fuzzer? Exiting.",
                si_addr
                );

                #[cfg(all(feature = "std", unix))]
                {
                    let mut writer = std::io::BufWriter::new(std::io::stderr());
                    crate::bolts::minibsod::generate_minibsod(&mut writer, signal, _info, _context)
                        .unwrap();
                    writer.flush().unwrap();
                }
            }

            #[cfg(feature = "std")]
            {
                eprintln!("Type QUIT to restart the child");
                let mut line = String::new();
                while line.trim() != "QUIT" {
                    std::io::stdin().read_line(&mut line).unwrap();
                }
            }

            // TODO tell the parent to not restart
        } else {
            let executor = (data.executor_ptr as *mut E).as_mut().unwrap();
            // disarms timeout in case of TimeoutExecutor
            executor.post_run_reset();
            let state = (data.state_ptr as *mut S).as_mut().unwrap();
            let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
            let fuzzer = (data.fuzzer_ptr as *mut Z).as_mut().unwrap();
            let observers = executor.observers_mut();

            let input = (data.current_input_ptr as *const I).as_ref().unwrap();
            data.current_input_ptr = ptr::null();

            #[cfg(feature = "std")]
            eprintln!("Triggering post_exec_all from crash_handler");

            observers
                .post_exec_all(state, input, &ExitKind::Crash)
                .expect("Observers post_exec_all failed");

            #[cfg(feature = "std")]
            eprintln!("Child crashed!");

            #[cfg(all(feature = "std", unix))]
            {
                let mut writer = std::io::BufWriter::new(std::io::stderr());
                writeln!(writer, "input: {:?}", input.generate_name(0)).unwrap();
                crate::bolts::minibsod::generate_minibsod(&mut writer, signal, _info, _context)
                    .unwrap();
                writer.flush().unwrap();
            }

            let interesting = fuzzer
                .objective_mut()
                .is_interesting(state, event_mgr, input, observers, &ExitKind::Crash)
                .expect("In crash handler objective failure.");

            if interesting {
                let new_input = input.clone();
                let mut new_testcase = Testcase::new(new_input);
                new_testcase.add_metadata(ExitKind::Crash);
                fuzzer
                    .objective_mut()
                    .append_metadata(state, &mut new_testcase)
                    .expect("Failed adding metadata");
                state
                    .solutions_mut()
                    .add(new_testcase)
                    .expect("In crash handler solutions failure.");
                event_mgr
                    .fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )
                    .expect("Could not send crashing input");
            }

            event_mgr.on_restart(state).unwrap();

            #[cfg(feature = "std")]
            eprintln!("Waiting for broker...");
            event_mgr.await_restart_safe();
            #[cfg(feature = "std")]
            eprintln!("Bye!");
        }

        libc::_exit(128 + (signal as i32));
    }
}

#[cfg(all(windows, feature = "std"))]
mod windows_exception_handler {
    use alloc::vec::Vec;
    use core::ffi::c_void;
    use core::{mem::transmute, ptr};
    #[cfg(feature = "std")]
    use std::io::{stdout, Write};

    use crate::{
        bolts::os::windows_exceptions::{
            ExceptionCode, Handler, CRASH_EXCEPTIONS, EXCEPTION_POINTERS,
        },
        corpus::{Corpus, Testcase},
        events::{Event, EventFirer, EventRestarter},
        executors::{
            inprocess::{InProcessExecutorHandlerData, GLOBAL_STATE},
            Executor, ExitKind, HasObservers,
        },
        feedbacks::Feedback,
        fuzzer::HasObjective,
        inputs::Input,
        observers::ObserversTuple,
        state::{HasClientPerfMonitor, HasMetadata, HasSolutions},
    };

    use core::sync::atomic::{compiler_fence, Ordering};
    use windows::Win32::System::Threading::ExitProcess;

    pub type HandlerFuncPtr = unsafe fn(*mut EXCEPTION_POINTERS, &mut InProcessExecutorHandlerData);

    /*pub unsafe fn nop_handler(
        _code: ExceptionCode,
        _exception_pointers: *mut EXCEPTION_POINTERS,
        _data: &mut InProcessExecutorHandlerData,
    ) {
    }*/

    impl Handler for InProcessExecutorHandlerData {
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        fn handle(&mut self, _code: ExceptionCode, exception_pointers: *mut EXCEPTION_POINTERS) {
            unsafe {
                let data = &mut GLOBAL_STATE;
                if !data.crash_handler.is_null() {
                    let func: HandlerFuncPtr = transmute(data.crash_handler);
                    (func)(exception_pointers, data);
                }
            }
        }

        fn exceptions(&self) -> Vec<ExceptionCode> {
            CRASH_EXCEPTIONS.to_vec()
        }
    }

    use windows::Win32::System::Threading::{
        EnterCriticalSection, LeaveCriticalSection, RTL_CRITICAL_SECTION,
    };

    pub unsafe extern "system" fn inproc_timeout_handler<E, EM, I, OF, OT, S, Z>(
        _p0: *mut u8,
        global_state: *mut c_void,
        _p1: *mut u8,
    ) where
        E: HasObservers<I, OT, S>,
        EM: EventFirer<I> + EventRestarter<S>,
        OT: ObserversTuple<I, S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        I: Input,
        Z: HasObjective<I, OF, S>,
    {
        let data: &mut InProcessExecutorHandlerData =
            &mut *(global_state as *mut InProcessExecutorHandlerData);
        compiler_fence(Ordering::SeqCst);
        EnterCriticalSection(
            (data.critical as *mut RTL_CRITICAL_SECTION)
                .as_mut()
                .unwrap(),
        );
        compiler_fence(Ordering::SeqCst);

        if data.in_target == 1 {
            let state = (data.state_ptr as *mut S).as_mut().unwrap();
            let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
            let fuzzer = (data.fuzzer_ptr as *mut Z).as_mut().unwrap();
            let executor = (data.executor_ptr as *const E).as_ref().unwrap();
            let observers = executor.observers();

            if data.timeout_input_ptr.is_null() {
                #[cfg(feature = "std")]
                dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing. Exiting");
            } else {
                #[cfg(feature = "std")]
                eprintln!("Timeout in fuzz run.");
                #[cfg(feature = "std")]
                let _res = stdout().flush();

                let input = (data.timeout_input_ptr as *const I).as_ref().unwrap();
                data.timeout_input_ptr = ptr::null_mut();

                let interesting = fuzzer
                    .objective_mut()
                    .is_interesting(state, event_mgr, input, observers, &ExitKind::Timeout)
                    .expect("In timeout handler objective failure.");

                if interesting {
                    let mut new_testcase = Testcase::new(input.clone());
                    new_testcase.add_metadata(ExitKind::Timeout);
                    fuzzer
                        .objective_mut()
                        .append_metadata(state, &mut new_testcase)
                        .expect("Failed adding metadata");
                    state
                        .solutions_mut()
                        .add(new_testcase)
                        .expect("In timeout handler solutions failure.");
                    event_mgr
                        .fire(
                            state,
                            Event::Objective {
                                objective_size: state.solutions().count(),
                            },
                        )
                        .expect("Could not send timeouting input");
                }

                event_mgr.on_restart(state).unwrap();

                #[cfg(feature = "std")]
                eprintln!("Waiting for broker...");
                event_mgr.await_restart_safe();
                #[cfg(feature = "std")]
                eprintln!("Bye!");

                event_mgr.await_restart_safe();
                compiler_fence(Ordering::SeqCst);

                ExitProcess(1);

                LeaveCriticalSection(
                    (data.critical as *mut RTL_CRITICAL_SECTION)
                        .as_mut()
                        .unwrap(),
                );
            }
        }
        compiler_fence(Ordering::SeqCst);
        LeaveCriticalSection(
            (data.critical as *mut RTL_CRITICAL_SECTION)
                .as_mut()
                .unwrap(),
        );
        compiler_fence(Ordering::SeqCst);
        // println!("TIMER INVOKED!");
    }

    pub unsafe fn inproc_crash_handler<E, EM, I, OF, OT, S, Z>(
        exception_pointers: *mut EXCEPTION_POINTERS,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: Executor<EM, I, S, Z> + HasObservers<I, OT, S>,
        EM: EventFirer<I> + EventRestarter<S>,
        OT: ObserversTuple<I, S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        I: Input,
        Z: HasObjective<I, OF, S>,
    {
        // Have we set a timer_before?
        if let Some(_) =
            (data.tp_timer as *mut windows::Win32::System::Threading::TP_TIMER).as_mut()
        {
            /*
                We want to prevent the timeout handler being run while the main thread is executing the crash handler
                Timeout handler runs if it has access to the critical section or data.in_target == 0
                Writing 0 to the data.in_target makes the timeout handler makes the timeout handler invalid.
            */
            compiler_fence(Ordering::SeqCst);
            EnterCriticalSection(data.critical as *mut RTL_CRITICAL_SECTION);
            compiler_fence(Ordering::SeqCst);
            data.in_target = 0;
            compiler_fence(Ordering::SeqCst);
            LeaveCriticalSection(data.critical as *mut RTL_CRITICAL_SECTION);
            compiler_fence(Ordering::SeqCst);
        }

        let code = ExceptionCode::try_from(
            exception_pointers
                .as_mut()
                .unwrap()
                .ExceptionRecord
                .as_mut()
                .unwrap()
                .ExceptionCode
                .0,
        )
        .unwrap();

        #[cfg(feature = "std")]
        eprintln!("Crashed with {}", code);
        if data.current_input_ptr.is_null() {
            #[cfg(feature = "std")]
            {
                eprintln!("Double crash\n");
                let crash_addr = exception_pointers
                    .as_mut()
                    .unwrap()
                    .ExceptionRecord
                    .as_mut()
                    .unwrap()
                    .ExceptionAddress as usize;

                eprintln!(
                "We crashed at addr 0x{:x}, but are not in the target... Bug in the fuzzer? Exiting.",
                    crash_addr
                );
            }
            #[cfg(feature = "std")]
            {
                eprintln!("Type QUIT to restart the child");
                let mut line = String::new();
                while line.trim() != "QUIT" {
                    std::io::stdin().read_line(&mut line).unwrap();
                }
            }

            // TODO tell the parent to not restart
        } else {
            let executor = (data.executor_ptr as *mut E).as_mut().unwrap();
            // reset timer
            if !data.tp_timer.is_null() {
                executor.post_run_reset();
                data.tp_timer = ptr::null_mut();
            }

            let state = (data.state_ptr as *mut S).as_mut().unwrap();
            let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
            let fuzzer = (data.fuzzer_ptr as *mut Z).as_mut().unwrap();
            let observers = executor.observers();

            #[cfg(feature = "std")]
            eprintln!("Child crashed!");
            #[cfg(feature = "std")]
            drop(stdout().flush());

            let input = (data.current_input_ptr as *const I).as_ref().unwrap();
            // Make sure we don't crash in the crash handler forever.
            data.current_input_ptr = ptr::null();

            let interesting = fuzzer
                .objective_mut()
                .is_interesting(state, event_mgr, input, observers, &ExitKind::Crash)
                .expect("In crash handler objective failure.");

            if interesting {
                let new_input = input.clone();
                let mut new_testcase = Testcase::new(new_input);
                new_testcase.add_metadata(ExitKind::Crash);
                fuzzer
                    .objective_mut()
                    .append_metadata(state, &mut new_testcase)
                    .expect("Failed adding metadata");
                state
                    .solutions_mut()
                    .add(new_testcase)
                    .expect("In crash handler solutions failure.");
                event_mgr
                    .fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )
                    .expect("Could not send crashing input");
            }

            event_mgr.on_restart(state).unwrap();

            #[cfg(feature = "std")]
            eprintln!("Waiting for broker...");
            event_mgr.await_restart_safe();
            #[cfg(feature = "std")]
            eprintln!("Bye!");
        }
        ExitProcess(1);
    }
}

/// The struct has [`InProcessHandlers`].
#[cfg(windows)]
pub trait HasInProcessHandlers {
    /// Get the in-process handlers.
    fn inprocess_handlers(&self) -> &InProcessHandlers;
}

#[cfg(windows)]
impl<'a, H, I, OT, S> HasInProcessHandlers for InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    /// the timeout handler
    #[inline]
    fn inprocess_handlers(&self) -> &InProcessHandlers {
        &self.handlers
    }
}

/// The signature of the crash handler function
#[cfg(all(feature = "std", unix))]
pub type ForkHandlerFuncPtr =
    unsafe fn(Signal, siginfo_t, &mut ucontext_t, data: &mut InProcessForkExecutorGlobalData);

/// The signature of the crash handler function
#[cfg(all(feature = "std", windows))]
pub type ForkHandlerFuncPtr =
    unsafe fn(*mut EXCEPTION_POINTERS, &mut InProcessForkExecutorGlobalData);

/// The inmem executor's handlers.
#[derive(Debug)]
pub struct InChildProcessHandlers {
    /// On crash C function pointer
    pub crash_handler: *const c_void,
}

#[cfg(feature = "std")]
impl InChildProcessHandlers {
    /// Call before running a target.
    pub fn pre_run_target<E, EM, I, S, Z>(
        &self,
        _executor: &E,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
        #[cfg(any(unix, windows))]
        unsafe {
            let data = &mut FORK_EXECUTOR_GLOBAL_DATA;
            write_volatile(
                &mut data.executor_ptr,
                _executor as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.current_input_ptr,
                _input as *const _ as *const c_void,
            );
            write_volatile(&mut data.state_ptr, _state as *mut _ as *mut c_void);
            data.crash_handler = self.crash_handler;
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Create new [`InChildProcessHandlers`].
    pub fn new<E, EM, I, OF, OT, S, Z>() -> Result<Self, Error>
    where
        I: Input,
        E: HasObservers<I, OT, S>,
        OT: ObserversTuple<I, S>,
        EM: EventFirer<I> + EventRestarter<S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        Z: HasObjective<I, OF, S>,
    {
        #[cfg(any(unix, windows))]
        // unsafe
        {
            // let data = &mut FORK_EXECUTOR_GLOBAL_DATA;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                crash_handler: bt_signal_handlers::child_crash_handler::<
                    E,
                    I,
                    OT,
                    S,
                    InProcessForkExecutorGlobalData,
                > as *const c_void,
            })
        }

        #[cfg(not(any(unix, all(windows, feature = "std"))))]
        Ok(Self {
            crash_handler: ptr::null(),
        })
    }

    /// Replace the handlers with `nop` handlers, deactivating the handlers
    #[must_use]
    pub fn nop() -> Self {
        Self {
            crash_handler: ptr::null(),
        }
    }
}

/// The global state of the in-process-fork harness.
#[derive(Debug)]
pub struct InProcessForkExecutorGlobalData {
    /// Stores a pointer to the fork executor struct
    pub executor_ptr: *const c_void,
    /// Stores a pointer to the state
    pub state_ptr: *const c_void,
    /// Stores a pointer to the current input
    pub current_input_ptr: *const c_void,
    /// Stores a pointer to the crash_handler function
    pub crash_handler: *const c_void,
}

unsafe impl Sync for InProcessForkExecutorGlobalData {}
unsafe impl Send for InProcessForkExecutorGlobalData {}

impl HasHandlerData for InProcessForkExecutorGlobalData {
    fn executor<E>(&self) -> &E {
        unsafe { (self.executor_ptr as *const E).as_ref().unwrap() }
    }

    fn executor_mut<E>(&self) -> &mut E {
        unsafe { (self.executor_ptr as *mut E).as_mut().unwrap() }
    }

    fn state<S>(&self) -> &S {
        unsafe { (self.state_ptr as *const S).as_ref().unwrap() }
    }

    fn state_mut<S>(&self) -> &mut S {
        unsafe { (self.state_ptr as *mut S).as_mut().unwrap() }
    }

    fn current_input<I>(&self) -> &I {
        unsafe { (self.current_input_ptr as *const I).as_ref().unwrap() }
    }

    fn is_valid(&self) -> bool {
        !self.current_input_ptr.is_null()
    }
}

/// a static variable storing the global state
pub static mut FORK_EXECUTOR_GLOBAL_DATA: InProcessForkExecutorGlobalData =
    InProcessForkExecutorGlobalData {
        executor_ptr: ptr::null(),
        crash_handler: ptr::null(),
        state_ptr: ptr::null(),
        current_input_ptr: ptr::null(),
    };

#[cfg(feature = "std")]
impl Handler for InProcessForkExecutorGlobalData {
    #[cfg(unix)]
    fn handle(&mut self, signal: Signal, info: siginfo_t, context: &mut ucontext_t) {
        match signal {
            Signal::SigUser2 | Signal::SigAlarm => (),
            _ => unsafe {
                if !FORK_EXECUTOR_GLOBAL_DATA.crash_handler.is_null() {
                    let func: ForkHandlerFuncPtr =
                        transmute(FORK_EXECUTOR_GLOBAL_DATA.crash_handler);
                    (func)(signal, info, context, &mut FORK_EXECUTOR_GLOBAL_DATA);
                }
            },
        }
    }

    #[cfg(unix)]
    fn signals(&self) -> Vec<Signal> {
        vec![
            Signal::SigAlarm,
            Signal::SigUser2,
            Signal::SigAbort,
            Signal::SigBus,
            Signal::SigPipe,
            Signal::SigFloatingPointException,
            Signal::SigIllegalInstruction,
            Signal::SigSegmentationFault,
            Signal::SigTrap,
        ]
    }

    #[cfg(windows)]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn handle(&mut self, _code: ExceptionCode, exception_pointers: *mut EXCEPTION_POINTERS) {
        unsafe {
            let data = &mut FORK_EXECUTOR_GLOBAL_DATA;
            if !data.crash_handler.is_null() {
                let func: ForkHandlerFuncPtr = transmute(data.crash_handler);
                (func)(exception_pointers, data);
            }
        }
    }

    #[cfg(windows)]
    fn exceptions(&self) -> Vec<ExceptionCode> {
        CRASH_EXCEPTIONS.to_vec()
    }
}

/// [`InProcessForkExecutor`] is an executor that forks the current process before each execution.
#[cfg(all(feature = "std", unix))]
pub struct InProcessForkExecutor<'a, H, I, OT, S, SP>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
{
    harness_fn: &'a mut H,
    shmem_provider: SP,
    observers: OT,
    handlers: InChildProcessHandlers,
    phantom: PhantomData<(I, S)>,
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, I, OT, S, SP> Debug for InProcessForkExecutor<'a, H, I, OT, S, SP>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessForkExecutor")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .finish()
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, EM, H, I, OT, S, SP, Z> Executor<EM, I, S, Z>
    for InProcessForkExecutor<'a, H, I, OT, S, SP>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
{
    #[allow(unreachable_code)]
    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        unsafe {
            self.shmem_provider.pre_fork()?;
            match fork() {
                Ok(ForkResult::Child) => {
                    // Child
                    self.shmem_provider.post_fork(true)?;

                    self.handlers
                        .pre_run_target(self, fuzzer, state, mgr, input);

                    match self
                        .observers()
                        .match_name::<BacktraceObserver>("BacktraceObserver")
                        .unwrap()
                        .harness_type()
                    {
                        crate::observers::HarnessType::FFI => {
                            setup_signal_handler(&mut FORK_EXECUTOR_GLOBAL_DATA)?;
                        }
                        crate::observers::HarnessType::RUST => {
                            setup_child_panic_hook::<
                                InProcessForkExecutor<H, I, OT, S, SP>,
                                I,
                                OT,
                                S,
                                InProcessForkExecutorGlobalData,
                            >(&FORK_EXECUTOR_GLOBAL_DATA);
                        }
                    }

                    (self.harness_fn)(input);

                    std::process::exit(0);

                    Ok(ExitKind::Ok)
                }
                Ok(ForkResult::Parent { child }) => {
                    // Parent
                    println!("from parent {} child is {}", std::process::id(), child);
                    self.shmem_provider.post_fork(false)?;
                    self.handlers
                        .pre_run_target(self, fuzzer, state, mgr, input);

                    let res = waitpid(child, None)?;

                    match res {
                        WaitStatus::Signaled(_, _, _) => Ok(ExitKind::Crash),
                        _ => Ok(ExitKind::Ok),
                    }
                }
                Err(e) => Err(Error::from(e)),
            }
        }
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, I, OT, S, SP> InProcessForkExecutor<'a, H, I, OT, S, SP>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
{
    /// Creates a new [`InProcessForkExecutor`]
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<I> + EventRestarter<S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        Z: HasObjective<I, OF, S>,
    {
        // should match on type when it's available
        let handlers = match observers.match_name::<BacktraceObserver>("BacktraceObserver") {
            Some(_) => {
                BacktraceObserver::setup_shmem();
                InChildProcessHandlers::new::<Self, EM, I, OF, OT, S, Z>()?
            }
            None => InChildProcessHandlers::nop(),
        };

        Ok(Self {
            harness_fn,
            shmem_provider,
            observers,
            handlers,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness_fn
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, I, OT, S, SP> HasObservers<I, OT, S> for InProcessForkExecutor<'a, H, I, OT, S, SP>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    SP: ShMemProvider,
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

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    #[cfg(all(feature = "std", feature = "fork", unix))]
    use crate::{
        bolts::shmem::{ShMemProvider, StdShMemProvider},
        executors::InProcessForkExecutor,
    };
    use crate::{
        bolts::tuples::tuple_list,
        executors::{inprocess::InProcessHandlers, Executor, ExitKind, InProcessExecutor},
        inputs::NopInput,
    };

    #[test]
    fn test_inmem_exec() {
        let mut harness = |_buf: &NopInput| ExitKind::Ok;

        let mut in_process_executor = InProcessExecutor::<_, NopInput, (), ()> {
            harness_fn: &mut harness,
            observers: tuple_list!(),
            handlers: InProcessHandlers::nop(),
            phantom: PhantomData,
        };
        let input = NopInput {};
        assert!(in_process_executor
            .run_target(&mut (), &mut (), &mut (), &input)
            .is_ok());
    }

    #[test]
    #[cfg(all(feature = "std", feature = "fork", unix))]
    fn test_inprocessfork_exec() {
        use crate::executors::inprocess::InChildProcessHandlers;

        let provider = StdShMemProvider::new().unwrap();

        let mut harness = |_buf: &NopInput| ExitKind::Ok;
        let mut in_process_fork_executor = InProcessForkExecutor::<_, NopInput, (), (), _> {
            harness_fn: &mut harness,
            shmem_provider: provider,
            observers: tuple_list!(),
            handlers: InChildProcessHandlers::nop(),
            phantom: PhantomData,
        };
        let input = NopInput {};
        assert!(in_process_fork_executor
            .run_target(&mut (), &mut (), &mut (), &input)
            .is_ok());
    }
}
