use core::{
    ffi::c_void,
    ptr::{self, null_mut, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(all(unix, not(miri)))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(windows, feature = "std"))]
use libafl_bolts::os::windows_exceptions::setup_exception_handler;
#[cfg(windows)]
use windows::Win32::System::Threading::{SetThreadStackGuarantee, PTP_TIMER};

#[cfg(unix)]
use crate::executors::hooks::unix::unix_signal_handler;
use crate::{
    events::{EventFirer, EventRestarter},
    executors::{Executor, HasObservers},
    feedbacks::Feedback,
    state::{HasCorpus, HasExecutions, HasSolutions},
    Error, HasObjective,
};
#[cfg(windows)]
use crate::{executors::inprocess::HasInProcessHandlers, state::State};
/// The inmem executor's handlers.
#[derive(Debug)]
pub struct InProcessHandlers {
    /// On crash C function pointer
    #[cfg(any(unix, feature = "std"))]
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    #[cfg(any(unix, feature = "std"))]
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
    #[cfg(not(all(windows, feature = "std")))]
    pub fn new<E, EM, OF, Z>() -> Result<Self, Error>
    where
        E: Executor<EM, Z> + HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        #[cfg(unix)]
        #[cfg_attr(miri, allow(unused_variables))]
        unsafe {
            let data = &mut GLOBAL_STATE;
            #[cfg(feature = "std")]
            unix_signal_handler::setup_panic_hook::<E, EM, OF, Z>();
            #[cfg(not(miri))]
            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                crash_handler: unix_signal_handler::inproc_crash_handler::<E, EM, OF, Z>
                    as *const c_void,
                timeout_handler: unix_signal_handler::inproc_timeout_handler::<E, EM, OF, Z>
                    as *const _,
            })
        }
        #[cfg(not(any(unix, feature = "std")))]
        Ok(Self {})
    }

    /// Create new [`InProcessHandlers`].
    #[cfg(all(windows, feature = "std"))]
    pub fn new<E, EM, OF, Z>() -> Result<Self, Error>
    where
        E: Executor<EM, Z> + HasObservers + HasInProcessHandlers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: State + HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        unsafe {
            let data = &mut GLOBAL_STATE;
            crate::executors::hooks::windows::windows_exception_handler::setup_panic_hook::<
                E,
                EM,
                OF,
                Z,
            >();
            setup_exception_handler(data)?;
            compiler_fence(Ordering::SeqCst);

            Ok(Self {
                crash_handler: crate::executors::hooks::windows::windows_exception_handler::inproc_crash_handler::<E, EM, OF, Z>
                    as *const _,
                timeout_handler: crate::executors::hooks::windows::windows_exception_handler::inproc_timeout_handler::<E, EM, OF, Z>
                    as *const c_void,
            })
        }
    }

    /// Replace the handlers with `nop` handlers, deactivating the handlers
    #[must_use]
    pub fn nop() -> Self {
        let ret;
        #[cfg(any(unix, feature = "std"))]
        {
            ret = Self {
                crash_handler: ptr::null(),
                timeout_handler: ptr::null(),
            };
        }
        #[cfg(not(any(unix, feature = "std")))]
        {
            ret = Self {};
        }
        ret
    }
}

/// The global state of the in-process harness.
#[derive(Debug)]
pub struct InProcessExecutorHandlerData {
    state_ptr: *mut c_void,
    event_mgr_ptr: *mut c_void,
    fuzzer_ptr: *mut c_void,
    executor_ptr: *const c_void,
    pub(crate) current_input_ptr: *const c_void,
    pub(crate) in_handler: bool,

    /// The timeout handler
    #[cfg(any(unix, feature = "std"))]
    pub(crate) crash_handler: *const c_void,
    /// The timeout handler
    #[cfg(any(unix, feature = "std"))]
    pub(crate) timeout_handler: *const c_void,

    #[cfg(all(windows, feature = "std"))]
    pub(crate) ptp_timer: Option<PTP_TIMER>,
    #[cfg(all(windows, feature = "std"))]
    pub(crate) in_target: u64,
    #[cfg(all(windows, feature = "std"))]
    pub(crate) critical: *mut c_void,
    #[cfg(all(windows, feature = "std"))]
    pub(crate) timeout_input_ptr: *mut c_void,

    #[cfg(any(unix, feature = "std"))]
    pub(crate) timeout_executor_ptr: *mut c_void,
}

unsafe impl Send for InProcessExecutorHandlerData {}
unsafe impl Sync for InProcessExecutorHandlerData {}

impl InProcessExecutorHandlerData {
    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn executor_mut<'a, E>(&self) -> &'a mut E {
        unsafe { (self.executor_ptr as *mut E).as_mut().unwrap() }
    }

    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn state_mut<'a, S>(&self) -> &'a mut S {
        unsafe { (self.state_ptr as *mut S).as_mut().unwrap() }
    }

    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn event_mgr_mut<'a, EM>(&self) -> &'a mut EM {
        unsafe { (self.event_mgr_ptr as *mut EM).as_mut().unwrap() }
    }

    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn fuzzer_mut<'a, Z>(&self) -> &'a mut Z {
        unsafe { (self.fuzzer_ptr as *mut Z).as_mut().unwrap() }
    }

    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn take_current_input<'a, I>(&mut self) -> &'a I {
        let r = unsafe { (self.current_input_ptr as *const I).as_ref().unwrap() };
        self.current_input_ptr = ptr::null();
        r
    }

    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn is_valid(&self) -> bool {
        !self.current_input_ptr.is_null()
    }

    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn timeout_executor_mut<'a, E>(
        &self,
    ) -> &'a mut crate::executors::timeout::TimeoutExecutor<E> {
        unsafe {
            (self.timeout_executor_ptr as *mut crate::executors::timeout::TimeoutExecutor<E>)
                .as_mut()
                .unwrap()
        }
    }

    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn set_in_handler(&mut self, v: bool) -> bool {
        let old = self.in_handler;
        self.in_handler = v;
        old
    }
}

/// Exception handling needs some nasty unsafe.
pub(crate) static mut GLOBAL_STATE: InProcessExecutorHandlerData = InProcessExecutorHandlerData {
    // The state ptr for signal handling
    state_ptr: null_mut(),
    // The event manager ptr for signal handling
    event_mgr_ptr: null_mut(),
    // The fuzzer ptr for signal handling
    fuzzer_ptr: null_mut(),
    // The executor ptr for signal handling
    executor_ptr: ptr::null(),
    // The current input for signal handling
    current_input_ptr: ptr::null(),

    in_handler: false,

    // The crash handler fn
    #[cfg(any(unix, feature = "std"))]
    crash_handler: ptr::null(),
    // The timeout handler fn
    #[cfg(any(unix, feature = "std"))]
    timeout_handler: ptr::null(),
    #[cfg(all(windows, feature = "std"))]
    ptp_timer: None,
    #[cfg(all(windows, feature = "std"))]
    in_target: 0,
    #[cfg(all(windows, feature = "std"))]
    critical: null_mut(),
    #[cfg(all(windows, feature = "std"))]
    timeout_input_ptr: null_mut(),

    #[cfg(any(unix, feature = "std"))]
    timeout_executor_ptr: null_mut(),
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

/// Gets the inprocess input
#[must_use]
pub fn inprocess_get_input<'a, I>() -> Option<&'a I> {
    unsafe { (GLOBAL_STATE.current_input_ptr as *const I).as_ref() }
}

/// Know if we ar eexecuting in a crash/timeout handler
#[must_use]
pub fn inprocess_in_handler() -> bool {
    unsafe { GLOBAL_STATE.in_handler }
}
