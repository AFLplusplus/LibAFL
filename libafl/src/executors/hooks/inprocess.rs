#[cfg(any(unix, all(windows, feature = "std")))]
use core::sync::atomic::{compiler_fence, Ordering};
use core::{
    ffi::c_void,
    ptr::{self, addr_of_mut, null_mut},
    time::Duration,
};

#[cfg(all(unix, not(miri)))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(windows, feature = "std"))]
use libafl_bolts::os::windows_exceptions::setup_exception_handler;
#[cfg(all(windows, feature = "std"))]
use windows::Win32::System::Threading::{
    CreateThreadpoolTimer, InitializeCriticalSection, CRITICAL_SECTION, PTP_CALLBACK_INSTANCE,
    PTP_TIMER, TP_CALLBACK_ENVIRON_V3,
};

#[cfg(feature = "std")]
use crate::executors::hooks::timer::TimerStruct;
#[cfg(unix)]
use crate::executors::hooks::unix::unix_signal_handler;
use crate::{
    events::{EventFirer, EventRestarter},
    executors::{hooks::ExecutorHook, Executor, HasObservers},
    feedbacks::Feedback,
    state::{HasCorpus, HasExecutions, HasSolutions},
    Error, HasObjective,
};
#[cfg(all(windows, feature = "std"))]
use crate::{executors::inprocess::HasInProcessHooks, state::State};
/// The inmem executor's handlers.
#[derive(Debug)]
pub struct InProcessHooks {
    /// On crash C function pointer
    #[cfg(any(unix, feature = "std"))]
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    #[cfg(any(unix, feature = "std"))]
    pub timeout_handler: *const c_void,
    /// TImer struct
    pub timer: TimerStruct,
}

/// Any hooks that is about timeout
pub trait HasTimeout {
    fn timer(&self) -> &TimerStruct;
    fn timer_mut(&mut self) -> &mut TimerStruct;
    #[cfg(all(feature = "std", windows))]
    fn ptp_timer(&self) -> &PTP_TIMER;
    #[cfg(all(feature = "std", windows))]
    fn critical(&self) -> &CRITICAL_SECTION;
    #[cfg(all(feature = "std", windows))]
    fn critical_mut(&mut self) -> &mut CRITICAL_SECTION;
    #[cfg(all(feature = "std", windows))]
    fn milli_sec(&self) -> i64;
    #[cfg(all(feature = "std", windows))]
    fn millis_sec_mut(&mut self) -> &mut i64;

    fn handle_timeout(&mut self) -> bool;
}

impl HasTimeout for InProcessHooks {
    fn timer(&self) -> &TimerStruct {
        &self.timer
    }

    fn timer_mut(&mut self) -> &mut TimerStruct {
        &mut self.timer
    }

    #[cfg(all(feature = "std", windows))]
    fn ptp_timer(&self) -> &PTP_TIMER {
        &self.timer().ptp_timer()
    }

    #[cfg(all(feature = "std", windows))]
    fn critical(&self) -> &CRITICAL_SECTION {
        &self.timer().critical()
    }

    #[cfg(all(feature = "std", windows))]
    fn critical_mut(&mut self) -> &mut CRITICAL_SECTION {
        self.timer_mut().critical_mut()
    }

    #[cfg(all(feature = "std", windows))]
    fn milli_sec(&self) -> i64 {
        self.timer().milli_sec()
    }

    #[cfg(all(feature = "std", windows))]
    fn millis_sec_mut(&mut self) -> &mut i64 {
        self.timer_mut().milli_sec_mut()
    }

    #[cfg(windows)]
    fn handle_timeout(&mut self) -> bool {
        false
    }

    #[cfg(unix)]
    fn handle_timeout(&mut self) {
        true
        // TODO!
    }
}

#[cfg(windows)]
#[allow(non_camel_case_types)]
type PTP_TIMER_CALLBACK = unsafe extern "system" fn(
    param0: PTP_CALLBACK_INSTANCE,
    param1: *mut c_void,
    param2: PTP_TIMER,
);

impl ExecutorHook for InProcessHooks {
    fn init<E: HasObservers, S>(&mut self, _state: &mut S) {
        // init timeout
        #[cfg(windows)]
        {
            #[cfg(feature = "std")]
            {
                let timeout_handler: PTP_TIMER_CALLBACK =
                    unsafe { std::mem::transmute(self.timeout_handler) };
                let ptp_timer = unsafe {
                    CreateThreadpoolTimer(
                        Some(timeout_handler),
                        Some(addr_of_mut!(GLOBAL_STATE) as *mut c_void),
                        Some(&TP_CALLBACK_ENVIRON_V3::default()),
                    )
                }
                .expect("CreateThreadpoolTimer failed!");
                let mut critical = CRITICAL_SECTION::default();

                unsafe {
                    InitializeCriticalSection(&mut critical);
                }

                *self.timer_mut().ptp_timer_mut() = ptp_timer;
                *self.timer_mut().critical_mut() = critical;
            }
        }
    }

    /// Call before running a target.
    #[allow(clippy::unused_self)]
    #[allow(unused_variables)]
    fn pre_exec<EM, I, S, Z>(&mut self, fuzzer: &mut Z, state: &mut S, mgr: &mut EM, input: &I) {
        let data = unsafe { &mut GLOBAL_STATE };
        data.crash_handler = self.crash_handler;
        data.timeout_handler = self.timeout_handler;
        self.timer_mut().set_timer();
    }

    /// Call after running a target.
    #[allow(clippy::unused_self)]
    fn post_exec<EM, I, S, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
        let data = unsafe { &mut GLOBAL_STATE };
        //timeout stuff
        self.timer_mut().unset_timer();
    }
}

impl InProcessHooks {
    /// Create new [`InProcessHooks`].
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

    /// Create new [`InProcessHooks`].
    #[cfg(all(windows, feature = "std"))]
    pub fn new<E, EM, OF, Z>(exec_tmout: Duration) -> Result<Self, Error>
    where
        E: Executor<EM, Z> + HasObservers + HasInProcessHooks,
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

            let ret;
            #[cfg(windows)]
            {
                #[cfg(feature = "std")]
                {
                    ret = Ok(Self {
                        crash_handler: crate::executors::hooks::windows::windows_exception_handler::inproc_crash_handler::<E, EM, OF, Z>
                            as *const _,
                        timeout_handler: crate::executors::hooks::windows::windows_exception_handler::inproc_timeout_handler::<E, EM, OF, Z>
                            as *const c_void,
                        timer: TimerStruct::new(exec_tmout),
                    });
                }
                #[cfg(not(feature = "std"))]
                {
                    ret =  Ok(Self {
                        crash_handler: crate::executors::hooks::windows::windows_exception_handler::inproc_crash_handler::<E, EM, OF, Z>
                            as *const _,
                        timeout_handler: crate::executors::hooks::windows::windows_exception_handler::inproc_timeout_handler::<E, EM, OF, Z>
                            as *const c_void,
                    }) ;
                }
            }

            ret
        }
    }

    /// Replace the handlers with `nop` handlers, deactivating the handlers
    #[must_use]
    pub fn nop() -> Self {
        let ret;

        #[cfg(windows)]
        {
            #[cfg(feature = "std")]
            {
                ret = Self {
                    crash_handler: ptr::null(),
                    timeout_handler: ptr::null(),
                    timer: TimerStruct::new(Duration::from_millis(5000)),
                };
            }
            #[cfg(not(feature = "std"))]
            {
                ret = Self {
                    crash_handler: ptr::null(),
                    timeout_handler: ptr::null(),
                };
            }
        }
        #[cfg(unix)]
        {
            ret = Self {
                crash_handler: ptr::null(),
                timeout_handler: ptr::null(),
            }
        }
        ret
    }
}

/// The global state of the in-process harness.
#[derive(Debug)]
pub struct InProcessExecutorHandlerData {
    /// the pointer to the state
    pub state_ptr: *mut c_void,
    /// the pointer to the event mgr
    pub event_mgr_ptr: *mut c_void,
    /// the pointer to the fuzzer
    pub fuzzer_ptr: *mut c_void,
    /// the pointer to the executor
    pub executor_ptr: *const c_void,
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
