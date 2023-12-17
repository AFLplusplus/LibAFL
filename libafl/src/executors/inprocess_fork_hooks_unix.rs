use alloc::vec::Vec;
use core::{
    ffi::c_void,
    ptr::{self, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
};
use std::intrinsics::transmute;

#[cfg(not(miri))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
use libafl_bolts::os::unix_signals::{ucontext_t, Handler, Signal};
use libc::siginfo_t;

use crate::{executors::HasObservers, Error};

/// The signature of the crash handler function
#[cfg(all(feature = "std", unix))]
pub(crate) type ForkHandlerFuncPtr = unsafe fn(
    Signal,
    &mut siginfo_t,
    Option<&mut ucontext_t>,
    data: &mut InChildDefaultExecutorHooksData,
);

/// The inmem fork executor's handlers.
#[cfg(all(feature = "std", unix))]
#[derive(Debug)]
pub struct InChildDefaultExecutorHooks {
    /// On crash C function pointer
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    pub timeout_handler: *const c_void,
}

#[cfg(all(feature = "std", unix))]
impl InChildDefaultExecutorHooks {
    /// Call before running a target.
    pub fn pre_run_target<E, I, S>(&self, executor: &E, state: &mut S, input: &I) {
        unsafe {
            let data = &mut FORK_EXECUTOR_GLOBAL_DATA;
            write_volatile(
                &mut data.executor_ptr,
                executor as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.current_input_ptr,
                input as *const _ as *const c_void,
            );
            write_volatile(&mut data.state_ptr, state as *mut _ as *mut c_void);
            data.crash_handler = self.crash_handler;
            data.timeout_handler = self.timeout_handler;
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Create new [`InChildDefaultExecutorHooks`].
    pub fn new<E>() -> Result<Self, Error>
    where
        E: HasObservers,
    {
        #[cfg_attr(miri, allow(unused_variables))]
        unsafe {
            let data = &mut FORK_EXECUTOR_GLOBAL_DATA;
            // child_signal_handlers::setup_child_panic_hook::<E, I, OT, S>();
            #[cfg(not(miri))]
            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                crash_handler: child_signal_handlers::child_crash_handler::<E> as *const c_void,
                timeout_handler: ptr::null(),
            })
        }
    }

    /// Create new [`InChildDefaultExecutorHooks`].
    pub fn with_timeout<E>() -> Result<Self, Error>
    where
        E: HasObservers,
    {
        #[cfg_attr(miri, allow(unused_variables))]
        unsafe {
            let data = &mut FORK_EXECUTOR_GLOBAL_DATA;
            // child_signal_handlers::setup_child_panic_hook::<E, I, OT, S>();
            #[cfg(not(miri))]
            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                crash_handler: child_signal_handlers::child_crash_handler::<E> as *const c_void,
                timeout_handler: child_signal_handlers::child_timeout_handler::<E> as *const c_void,
            })
        }
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

/// The global state of the in-process-fork harness.
#[cfg(all(feature = "std", unix))]
#[derive(Debug)]
pub(crate) struct InChildDefaultExecutorHooksData {
    /// Stores a pointer to the fork executor struct
    pub executor_ptr: *const c_void,
    /// Stores a pointer to the state
    pub state_ptr: *const c_void,
    /// Stores a pointer to the current input
    pub current_input_ptr: *const c_void,
    /// Stores a pointer to the crash_handler function
    pub crash_handler: *const c_void,
    /// Stores a pointer to the timeout_handler function
    pub timeout_handler: *const c_void,
}

#[cfg(all(feature = "std", unix))]
unsafe impl Sync for InChildDefaultExecutorHooksData {}
#[cfg(all(feature = "std", unix))]
unsafe impl Send for InChildDefaultExecutorHooksData {}

#[cfg(all(feature = "std", unix))]
impl InChildDefaultExecutorHooksData {
    fn executor_mut<'a, E>(&self) -> &'a mut E {
        unsafe { (self.executor_ptr as *mut E).as_mut().unwrap() }
    }

    fn state_mut<'a, S>(&self) -> &'a mut S {
        unsafe { (self.state_ptr as *mut S).as_mut().unwrap() }
    }

    /*fn current_input<'a, I>(&self) -> &'a I {
        unsafe { (self.current_input_ptr as *const I).as_ref().unwrap() }
    }*/

    fn take_current_input<'a, I>(&mut self) -> &'a I {
        let r = unsafe { (self.current_input_ptr as *const I).as_ref().unwrap() };
        self.current_input_ptr = ptr::null();
        r
    }

    fn is_valid(&self) -> bool {
        !self.current_input_ptr.is_null()
    }
}

/// a static variable storing the global state
#[cfg(all(feature = "std", unix))]
pub(crate) static mut FORK_EXECUTOR_GLOBAL_DATA: InChildDefaultExecutorHooksData =
    InChildDefaultExecutorHooksData {
        executor_ptr: ptr::null(),
        state_ptr: ptr::null(),
        current_input_ptr: ptr::null(),
        crash_handler: ptr::null(),
        timeout_handler: ptr::null(),
    };

#[cfg(all(feature = "std", unix))]
impl Handler for InChildDefaultExecutorHooksData {
    fn handle(&mut self, signal: Signal, info: &mut siginfo_t, context: Option<&mut ucontext_t>) {
        match signal {
            Signal::SigUser2 | Signal::SigAlarm => unsafe {
                if !FORK_EXECUTOR_GLOBAL_DATA.timeout_handler.is_null() {
                    let func: ForkHandlerFuncPtr =
                        transmute(FORK_EXECUTOR_GLOBAL_DATA.timeout_handler);
                    (func)(signal, info, context, &mut FORK_EXECUTOR_GLOBAL_DATA);
                }
            },
            _ => unsafe {
                if !FORK_EXECUTOR_GLOBAL_DATA.crash_handler.is_null() {
                    let func: ForkHandlerFuncPtr =
                        transmute(FORK_EXECUTOR_GLOBAL_DATA.crash_handler);
                    (func)(signal, info, context, &mut FORK_EXECUTOR_GLOBAL_DATA);
                }
            },
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

/// signal handlers and `panic_hooks` for the child process
#[cfg(all(feature = "std", unix))]
pub mod child_signal_handlers {
    use alloc::boxed::Box;
    use std::panic;

    use libafl_bolts::os::unix_signals::{ucontext_t, Signal};
    use libc::siginfo_t;

    use super::{InChildDefaultExecutorHooksData, FORK_EXECUTOR_GLOBAL_DATA};
    use crate::{
        executors::{ExitKind, HasObservers},
        inputs::UsesInput,
        observers::ObserversTuple,
    };

    /// invokes the `post_exec_child` hook on all observer in case the child process panics
    pub fn setup_child_panic_hook<E>()
    where
        E: HasObservers,
    {
        let old_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            old_hook(panic_info);
            let data = unsafe { &mut FORK_EXECUTOR_GLOBAL_DATA };
            if data.is_valid() {
                let executor = data.executor_mut::<E>();
                let observers = executor.observers_mut();
                let state = data.state_mut::<E::State>();
                // Invalidate data to not execute again the observer hooks in the crash handler
                let input = data.take_current_input::<<E::State as UsesInput>::Input>();
                observers
                    .post_exec_child_all(state, input, &ExitKind::Crash)
                    .expect("Failed to run post_exec on observers");

                // std::process::abort();
                unsafe { libc::_exit(128 + 6) }; // ABORT exit code
            }
        }));
    }

    /// invokes the `post_exec` hook on all observer in case the child process crashes
    ///
    /// # Safety
    /// The function should only be called from a child crash handler.
    /// It will dereference the `data` pointer and assume it's valid.
    #[cfg(unix)]
    pub(crate) unsafe fn child_crash_handler<E>(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
        data: &mut InChildDefaultExecutorHooksData,
    ) where
        E: HasObservers,
    {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let observers = executor.observers_mut();
            let state = data.state_mut::<E::State>();
            let input = data.take_current_input::<<E::State as UsesInput>::Input>();
            observers
                .post_exec_child_all(state, input, &ExitKind::Crash)
                .expect("Failed to run post_exec on observers");
        }

        libc::_exit(128 + (_signal as i32));
    }

    #[cfg(unix)]
    pub(crate) unsafe fn child_timeout_handler<E>(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
        data: &mut InChildDefaultExecutorHooksData,
    ) where
        E: HasObservers,
    {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let observers = executor.observers_mut();
            let state = data.state_mut::<E::State>();
            let input = data.take_current_input::<<E::State as UsesInput>::Input>();
            observers
                .post_exec_child_all(state, input, &ExitKind::Timeout)
                .expect("Failed to run post_exec on observers");
        }
        libc::_exit(128 + (_signal as i32));
    }
}
