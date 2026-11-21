//! The hook for the `InProcessForkExecutor`
use alloc::vec::Vec;
use core::{
    ffi::c_void,
    marker::PhantomData,
    mem::transmute,
    ptr::{null, null_mut},
    sync::atomic::{AtomicPtr, Ordering},
};

#[cfg(not(miri))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
use libafl_bolts::os::unix_signals::{Signal, SignalHandler, ucontext_t};
use libc::siginfo_t;

use crate::{
    Error,
    executors::{
        HasObservers, common_signals,
        hooks::ExecutorHook,
        inprocess_fork::{ForkHandlerFuncPtr, child_signal_handlers},
    },
    observers::ObserversTuple,
};

/// Sentinel placed in `current_input_ptr` while a crash/timeout/panic handler owns teardown.
static HANDLER_CLAIMED: u8 = 0;

#[inline]
fn claimed_ptr() -> *mut c_void {
    (&raw const HANDLER_CLAIMED).cast_mut().cast()
}

/// The inmem fork executor's hooks.
#[derive(Debug)]
pub struct InChildProcessHooks<I, S> {
    /// On crash C function pointer
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    pub timeout_handler: *const c_void,
    phantom: PhantomData<(I, S)>,
}

impl<I, S> ExecutorHook<I, S> for InChildProcessHooks<I, S> {
    /// Init this hook
    fn init(&mut self, _state: &mut S) {}

    /// Call before running a target.
    fn pre_exec(&mut self, _state: &mut S, _input: &I) {
        FORK_EXECUTOR_GLOBAL_DATA
            .crash_handler
            .store(self.crash_handler.cast_mut(), Ordering::Release);
        FORK_EXECUTOR_GLOBAL_DATA
            .timeout_handler
            .store(self.timeout_handler.cast_mut(), Ordering::Release);
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I) {
        FORK_EXECUTOR_GLOBAL_DATA
            .crash_handler
            .store(null_mut(), Ordering::Release);
        FORK_EXECUTOR_GLOBAL_DATA
            .timeout_handler
            .store(null_mut(), Ordering::Release);
    }
}

impl<I, S> InChildProcessHooks<I, S> {
    /// Create new [`InChildProcessHooks`].
    pub fn new<E>() -> Result<Self, Error>
    where
        E: HasObservers,
        E::Observers: ObserversTuple<I, S>,
    {
        #[cfg(not(miri))]
        unsafe {
            setup_signal_handler(core::ptr::NonNull::<ForkSignalHandler>::dangling().as_ptr())?;
        }
        Ok(Self {
            crash_handler: child_signal_handlers::child_crash_handler::<E, I, S> as *const c_void,
            timeout_handler: child_signal_handlers::child_timeout_handler::<E, I, S>
                as *const c_void,
            phantom: PhantomData,
        })
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
    pub executor_ptr: AtomicPtr<c_void>,
    /// Stores a pointer to the state
    pub state_ptr: AtomicPtr<c_void>,
    /// Stores a pointer to the current input
    pub current_input_ptr: AtomicPtr<c_void>,
    /// Stores a pointer to the `crash_handler` function
    pub crash_handler: AtomicPtr<c_void>,
    /// Stores a pointer to the `timeout_handler` function
    pub timeout_handler: AtomicPtr<c_void>,
}

impl InProcessForkExecutorGlobalData {
    /// # Safety
    /// Only safe if not called twice and if the executor is not used from another borrow after this.
    pub(crate) unsafe fn executor_mut<'a, E>(&self) -> &'a mut E {
        let ptr = self.executor_ptr.load(Ordering::Acquire).cast::<E>();
        unsafe { ptr.as_mut().unwrap() }
    }

    /// # Safety
    /// Only safe if not called twice and if the state is not used from another borrow after this.
    pub(crate) unsafe fn state_mut<'a, S>(&self) -> &'a mut S {
        let ptr = self.state_ptr.load(Ordering::Acquire).cast::<S>();
        unsafe { ptr.as_mut().unwrap() }
    }

    /// Atomically claims `current_input_ptr` so at most one panic/signal handler runs observers.
    ///
    /// # Safety
    /// Any non-null, non-sentinel pointer in `current_input_ptr` must point to a valid `I` for `'a`,
    /// and a caller receiving `Some` must terminate the child (`_exit`) without returning.
    pub(crate) unsafe fn take_current_input<'a, I>(&self) -> Option<&'a I> {
        let claimed = claimed_ptr();
        let mut cur = self.current_input_ptr.load(Ordering::Acquire);
        loop {
            if cur.is_null() || cur == claimed {
                return None;
            }
            match self.current_input_ptr.compare_exchange_weak(
                cur,
                claimed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return unsafe { Some(&*cur.cast::<I>()) },
                Err(actual) => cur = actual,
            }
        }
    }

    #[inline]
    pub(crate) fn leave_or_wait(&self) {
        if self.current_input_ptr.swap(null_mut(), Ordering::AcqRel) == claimed_ptr() {
            loop {
                unsafe {
                    libc::pause();
                }
            }
        }
        self.executor_ptr.store(null_mut(), Ordering::Release);
        self.state_ptr.store(null_mut(), Ordering::Release);
    }
}

/// Atomic static variable storing the global in-process-fork state.
pub(crate) static FORK_EXECUTOR_GLOBAL_DATA: InProcessForkExecutorGlobalData =
    InProcessForkExecutorGlobalData {
        executor_ptr: AtomicPtr::new(null_mut()),
        state_ptr: AtomicPtr::new(null_mut()),
        current_input_ptr: AtomicPtr::new(null_mut()),
        crash_handler: AtomicPtr::new(null_mut()),
        timeout_handler: AtomicPtr::new(null_mut()),
    };

#[cfg_attr(miri, allow(dead_code))]
struct ForkSignalHandler;

impl SignalHandler for ForkSignalHandler {
    unsafe fn handle(
        &mut self,
        signal: Signal,
        info: &mut siginfo_t,
        context: Option<&mut ucontext_t>,
    ) {
        match signal {
            Signal::SigUser2 | Signal::SigAlarm => unsafe {
                let handler = FORK_EXECUTOR_GLOBAL_DATA
                    .timeout_handler
                    .load(Ordering::Acquire);
                if !handler.is_null() {
                    let func: ForkHandlerFuncPtr = transmute(handler.cast_const());
                    (func)(signal, info, context, &FORK_EXECUTOR_GLOBAL_DATA);
                }
            },
            _ => unsafe {
                let handler = FORK_EXECUTOR_GLOBAL_DATA
                    .crash_handler
                    .load(Ordering::Acquire);
                if !handler.is_null() {
                    let func: ForkHandlerFuncPtr = transmute(handler.cast_const());
                    (func)(signal, info, context, &FORK_EXECUTOR_GLOBAL_DATA);
                }
            },
        }
    }

    fn signals(&self) -> Vec<Signal> {
        common_signals()
    }
}
