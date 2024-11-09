//! The hook for the `InProcessForkExecutor`
use alloc::vec::Vec;
use core::{
    ffi::c_void,
    marker::PhantomData,
    ptr::null,
    sync::atomic::{compiler_fence, Ordering},
};
use std::intrinsics::transmute;

#[cfg(not(miri))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
use libafl_bolts::os::unix_signals::{ucontext_t, Signal, SignalHandler};
use libc::siginfo_t;

use crate::{
    executors::{
        common_signals,
        hooks::ExecutorHook,
        inprocess_fork::{child_signal_handlers, ForkHandlerFuncPtr},
        HasObservers,
    },
    inputs::UsesInput,
    observers::ObserversTuple,
    state::UsesState,
    Error,
};

/// The inmem fork executor's hooks.
#[derive(Debug)]
pub struct InChildProcessHooks<S> {
    /// On crash C function pointer
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    pub timeout_handler: *const c_void,
    phantom: PhantomData<S>,
}

impl<S> ExecutorHook<S> for InChildProcessHooks<S>
where
    S: UsesInput,
{
    /// Init this hook
    fn init<E: HasObservers>(&mut self, _state: &mut S) {}

    /// Call before running a target.
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) {
        unsafe {
            let data = &raw mut FORK_EXECUTOR_GLOBAL_DATA;
            (*data).crash_handler = self.crash_handler;
            (*data).timeout_handler = self.timeout_handler;
            compiler_fence(Ordering::SeqCst);
        }
    }

    fn post_exec(&mut self, _state: &mut S, _input: &S::Input) {}
}

impl<S> InChildProcessHooks<S> {
    /// Create new [`InChildProcessHooks`].
    pub fn new<E>() -> Result<Self, Error>
    where
        E: HasObservers + UsesState,
        E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
    {
        #[cfg_attr(miri, allow(unused_variables, unused_unsafe))]
        unsafe {
            let data = &raw mut FORK_EXECUTOR_GLOBAL_DATA;
            // child_signal_handlers::setup_child_panic_hook::<E, I, OT, S>();
            #[cfg(not(miri))]
            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                crash_handler: child_signal_handlers::child_crash_handler::<E> as *const c_void,
                timeout_handler: child_signal_handlers::child_timeout_handler::<E> as *const c_void,
                phantom: PhantomData,
            })
        }
    }

    /// Replace the hooks with `nop` hooks, deactivating the hooks
    #[must_use]
    pub fn nop() -> Self {
        Self {
            crash_handler: null(),
            timeout_handler: null(),
            phantom: PhantomData,
        }
    }
}

/// The global state of the in-process-fork harness.

#[derive(Debug)]
pub(crate) struct InProcessForkExecutorGlobalData {
    /// Stores a pointer to the fork executor struct
    pub executor_ptr: *const c_void,
    /// Stores a pointer to the state
    pub state_ptr: *const c_void,
    /// Stores a pointer to the current input
    pub current_input_ptr: *const c_void,
    /// Stores a pointer to the `crash_handler` function
    pub crash_handler: *const c_void,
    /// Stores a pointer to the `timeout_handler` function
    pub timeout_handler: *const c_void,
}

unsafe impl Sync for InProcessForkExecutorGlobalData {}

unsafe impl Send for InProcessForkExecutorGlobalData {}

impl InProcessForkExecutorGlobalData {
    /// # Safety
    /// Only safe if not called twice and if the executor is not used from another borrow after this.
    pub(crate) unsafe fn executor_mut<'a, E>(&self) -> &'a mut E {
        unsafe { (self.executor_ptr as *mut E).as_mut().unwrap() }
    }

    /// # Safety
    /// Only safe if not called twice and if the state is not used from another borrow after this.
    pub(crate) unsafe fn state_mut<'a, S>(&self) -> &'a mut S {
        unsafe { (self.state_ptr as *mut S).as_mut().unwrap() }
    }

    /// # Safety
    /// Only safe if not called concurrently.
    pub(crate) unsafe fn take_current_input<'a, I>(&mut self) -> &'a I {
        let r = unsafe { (self.current_input_ptr as *const I).as_ref().unwrap() };
        self.current_input_ptr = null();
        r
    }

    pub(crate) fn is_valid(&self) -> bool {
        !self.current_input_ptr.is_null()
    }
}

/// a static variable storing the global state
pub(crate) static mut FORK_EXECUTOR_GLOBAL_DATA: InProcessForkExecutorGlobalData =
    InProcessForkExecutorGlobalData {
        executor_ptr: null(),
        state_ptr: null(),
        current_input_ptr: null(),
        crash_handler: null(),
        timeout_handler: null(),
    };

impl SignalHandler for InProcessForkExecutorGlobalData {
    unsafe fn handle(
        &mut self,
        signal: Signal,
        info: &mut siginfo_t,
        context: Option<&mut ucontext_t>,
    ) {
        match signal {
            Signal::SigUser2 | Signal::SigAlarm => unsafe {
                if !FORK_EXECUTOR_GLOBAL_DATA.timeout_handler.is_null() {
                    let func: ForkHandlerFuncPtr =
                        transmute(FORK_EXECUTOR_GLOBAL_DATA.timeout_handler);
                    (func)(signal, info, context, &raw mut FORK_EXECUTOR_GLOBAL_DATA);
                }
            },
            _ => unsafe {
                if !FORK_EXECUTOR_GLOBAL_DATA.crash_handler.is_null() {
                    let func: ForkHandlerFuncPtr =
                        transmute(FORK_EXECUTOR_GLOBAL_DATA.crash_handler);
                    (func)(signal, info, context, &raw mut FORK_EXECUTOR_GLOBAL_DATA);
                }
            },
        }
    }

    fn signals(&self) -> Vec<Signal> {
        common_signals()
    }
}
