//! The hook for `InProcessExecutor`
#[cfg(any(unix, feature = "std"))]
use core::ptr::addr_of_mut;
#[cfg(any(unix, all(windows, feature = "std")))]
use core::sync::atomic::{compiler_fence, Ordering};
use core::{
    ffi::c_void,
    marker::PhantomData,
    ptr::{self, null_mut},
    time::Duration,
};
#[cfg(all(target_os = "linux", feature = "std"))]
use core::{mem::zeroed, ptr::addr_of};

#[cfg(all(target_os = "linux", feature = "std"))]
use libafl_bolts::current_time;
#[cfg(all(unix, feature = "std", not(miri)))]
use libafl_bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(windows, feature = "std"))]
use libafl_bolts::os::windows_exceptions::setup_exception_handler;
#[cfg(all(windows, feature = "std"))]
use windows::Win32::System::Threading::{CRITICAL_SECTION, PTP_TIMER};

#[cfg(feature = "std")]
use crate::executors::hooks::timer::TimerStruct;
#[cfg(all(unix, feature = "std"))]
use crate::executors::hooks::unix::unix_signal_handler;
#[cfg(windows)]
use crate::state::State;
use crate::{
    events::{EventFirer, EventRestarter},
    executors::{hooks::ExecutorHook, inprocess::HasInProcessHooks, Executor, HasObservers},
    feedbacks::Feedback,
    inputs::UsesInput,
    state::{HasCorpus, HasExecutions, HasSolutions},
    Error, HasObjective,
};
/// The inmem executor's handlers.
#[allow(missing_debug_implementations)]
pub struct InProcessHooks<S>
where
    S: UsesInput,
{
    /// On crash C function pointer
    #[cfg(feature = "std")]
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    #[cfg(feature = "std")]
    pub timeout_handler: *const c_void,
    /// `TImer` struct
    #[cfg(feature = "std")]
    pub timer: TimerStruct,
    phantom: PhantomData<S>,
}

/// Any hooks that is about timeout
pub trait HasTimeout {
    /// Return ref to timer
    #[cfg(feature = "std")]
    fn timer(&self) -> &TimerStruct;
    /// Return mut ref to timer
    #[cfg(feature = "std")]
    fn timer_mut(&mut self) -> &mut TimerStruct;
    #[cfg(all(feature = "std", windows))]
    /// The timer object
    #[cfg(all(feature = "std", windows))]
    fn ptp_timer(&self) -> &PTP_TIMER;
    #[cfg(all(feature = "std", windows))]
    /// The critical section
    fn critical(&self) -> &CRITICAL_SECTION;
    #[cfg(all(feature = "std", windows))]
    /// The critical section (mut)
    fn critical_mut(&mut self) -> &mut CRITICAL_SECTION;
    #[cfg(all(feature = "std", windows))]
    /// The timeout in milli sec
    #[cfg(all(feature = "std", windows))]
    fn milli_sec(&self) -> i64;
    #[cfg(all(feature = "std", windows))]
    /// The timeout in milli sec (mut ref)
    fn millis_sec_mut(&mut self) -> &mut i64;
    #[cfg(not(all(unix, feature = "std")))]
    /// Handle timeout for batch mode timeout
    fn handle_timeout(&mut self) -> bool;
    #[cfg(all(unix, feature = "std"))]
    /// Handle timeout for batch mode timeout
    fn handle_timeout(&mut self, data: &mut InProcessExecutorHandlerData) -> bool;
}

impl<S> HasTimeout for InProcessHooks<S>
where
    S: UsesInput,
{
    #[cfg(feature = "std")]
    fn timer(&self) -> &TimerStruct {
        &self.timer
    }
    #[cfg(feature = "std")]
    fn timer_mut(&mut self) -> &mut TimerStruct {
        &mut self.timer
    }

    #[cfg(all(feature = "std", windows))]
    fn ptp_timer(&self) -> &PTP_TIMER {
        self.timer().ptp_timer()
    }

    #[cfg(all(feature = "std", windows))]
    fn critical(&self) -> &CRITICAL_SECTION {
        self.timer().critical()
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

    #[cfg(not(all(unix, feature = "std")))]
    fn handle_timeout(&mut self) -> bool {
        false
    }

    #[cfg(all(unix, feature = "std"))]
    #[allow(unused)]
    fn handle_timeout(&mut self, data: &mut InProcessExecutorHandlerData) -> bool {
        #[cfg(not(target_os = "linux"))]
        {
            false
        }

        #[cfg(target_os = "linux")]
        {
            if !self.timer().batch_mode {
                return false;
            }
            //eprintln!("handle_timeout {:?} {}", self.avg_exec_time, self.avg_mul_k);
            let cur_time = current_time();
            if !data.is_valid() {
                // outside the target
                unsafe {
                    let disarmed: libc::itimerspec = zeroed();
                    libc::timer_settime(
                        self.timer_mut().timerid,
                        0,
                        addr_of!(disarmed),
                        null_mut(),
                    );
                }
                let elapsed = cur_time - self.timer().tmout_start_time;
                // set timer the next exec
                if self.timer().executions > 0 {
                    self.timer_mut().avg_exec_time = elapsed / self.timer().executions;
                    self.timer_mut().executions = 0;
                }
                self.timer_mut().avg_mul_k += 1;
                self.timer_mut().last_signal_time = cur_time;
                return true;
            }

            let elapsed_run = cur_time - self.timer_mut().start_time;
            if elapsed_run < self.timer_mut().exec_tmout {
                // fp, reset timeout
                unsafe {
                    libc::timer_settime(
                        self.timer_mut().timerid,
                        0,
                        addr_of!(self.timer_mut().itimerspec),
                        null_mut(),
                    );
                }
                if self.timer().executions > 0 {
                    let elapsed = cur_time - self.timer_mut().tmout_start_time;
                    self.timer_mut().avg_exec_time = elapsed / self.timer().executions;
                    self.timer_mut().executions = 0; // It will be 1 when the exec finish
                }
                self.timer_mut().tmout_start_time = current_time();
                self.timer_mut().avg_mul_k += 1;
                self.timer_mut().last_signal_time = cur_time;
                true
            } else {
                false
            }
        }
    }
}

impl<S> ExecutorHook<S> for InProcessHooks<S>
where
    S: UsesInput,
{
    fn init<E: HasObservers>(&mut self, _state: &mut S) {}
    /// Call before running a target.
    #[allow(clippy::unused_self)]
    #[allow(unused_variables)]
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) {
        #[cfg(feature = "std")]
        unsafe {
            let data = addr_of_mut!(GLOBAL_STATE);
            (*data).crash_handler = self.crash_handler;
            (*data).timeout_handler = self.timeout_handler;
        }

        #[cfg(all(feature = "std", not(all(miri, target_vendor = "apple"))))]
        self.timer_mut().set_timer();
    }

    /// Call after running a target.
    #[allow(clippy::unused_self)]
    fn post_exec(&mut self, _state: &mut S, _input: &S::Input) {
        // timeout stuff
        #[cfg(all(feature = "std", not(all(miri, target_vendor = "apple"))))]
        self.timer_mut().unset_timer();
    }
}

impl<S> InProcessHooks<S>
where
    S: UsesInput,
{
    /// Create new [`InProcessHooks`].
    #[cfg(unix)]
    #[allow(unused_variables)]
    pub fn new<E, EM, OF, Z>(exec_tmout: Duration) -> Result<Self, Error>
    where
        E: Executor<EM, Z> + HasObservers + HasInProcessHooks<E::State>,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        #[cfg_attr(miri, allow(unused_variables))]
        unsafe {
            let data = addr_of_mut!(GLOBAL_STATE);
            #[cfg(feature = "std")]
            unix_signal_handler::setup_panic_hook::<E, EM, OF, Z>();
            #[cfg(all(not(miri), unix, feature = "std"))]
            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                #[cfg(feature = "std")]
                crash_handler: unix_signal_handler::inproc_crash_handler::<E, EM, OF, Z>
                    as *const c_void,
                #[cfg(feature = "std")]
                timeout_handler: unix_signal_handler::inproc_timeout_handler::<E, EM, OF, Z>
                    as *const _,
                #[cfg(feature = "std")]
                timer: TimerStruct::new(exec_tmout),
                phantom: PhantomData,
            })
        }
    }

    /// Create new [`InProcessHooks`].
    #[cfg(windows)]
    #[allow(unused)]
    pub fn new<E, EM, OF, Z>(exec_tmout: Duration) -> Result<Self, Error>
    where
        E: Executor<EM, Z> + HasObservers + HasInProcessHooks<E::State>,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: State + HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        let ret;
        #[cfg(feature = "std")]
        unsafe {
            let data = addr_of_mut!(GLOBAL_STATE);
            crate::executors::hooks::windows::windows_exception_handler::setup_panic_hook::<
                E,
                EM,
                OF,
                Z,
            >();
            setup_exception_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            let crash_handler =
                crate::executors::hooks::windows::windows_exception_handler::inproc_crash_handler::<
                    E,
                    EM,
                    OF,
                    Z,
                > as *const _;
            let timeout_handler =
                crate::executors::hooks::windows::windows_exception_handler::inproc_timeout_handler::<
                    E,
                    EM,
                    OF,
                    Z,
                > as *const c_void;
            let timer = TimerStruct::new(exec_tmout, timeout_handler);
            ret = Ok(Self {
                crash_handler,
                timeout_handler,
                timer,
                phantom: PhantomData,
            });
        }
        #[cfg(not(feature = "std"))]
        {
            ret = Ok(Self {
                phantom: PhantomData,
            });
        }

        ret
    }

    /// Create a new [`InProcessHooks`]
    #[cfg(all(not(unix), not(windows)))]
    #[allow(unused_variables)]
    pub fn new<E, EM, OF, Z>(exec_tmout: Duration) -> Result<Self, Error>
    where
        E: Executor<EM, Z> + HasObservers + HasInProcessHooks<E::State>,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        #[cfg_attr(miri, allow(unused_variables))]
        let ret = Self {
            phantom: PhantomData,
        };
        Ok(ret)
    }

    /// Replace the handlers with `nop` handlers, deactivating the handlers
    #[must_use]
    #[cfg(not(windows))]
    pub fn nop() -> Self {
        Self {
            #[cfg(feature = "std")]
            crash_handler: ptr::null(),
            #[cfg(feature = "std")]
            timeout_handler: ptr::null(),
            #[cfg(feature = "std")]
            timer: TimerStruct::new(Duration::from_millis(5000)),
            phantom: PhantomData,
        }
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
    #[cfg(feature = "std")]
    pub(crate) crash_handler: *const c_void,
    /// The timeout handler
    #[cfg(feature = "std")]
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
    #[cfg(feature = "std")]
    crash_handler: ptr::null(),
    // The timeout handler fn
    #[cfg(feature = "std")]
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
