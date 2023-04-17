//! A `TimeoutExecutor` sets a timeout before each target run

#[cfg(target_os = "linux")]
use core::ptr::{addr_of, addr_of_mut};
#[cfg(any(windows, target_os = "linux"))]
use core::{ffi::c_void, ptr::write_volatile};
#[cfg(any(windows, unix))]
use core::{
    fmt::{self, Debug, Formatter},
    time::Duration,
};
#[cfg(unix)]
use core::{mem::zeroed, ptr::null_mut};
#[cfg(windows)]
use core::{
    ptr::addr_of_mut,
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(all(unix, not(target_os = "linux")))]
use libc::c_int;
#[cfg(all(windows, feature = "std"))]
use windows::Win32::{
    Foundation::FILETIME,
    System::Threading::{
        CreateThreadpoolTimer, EnterCriticalSection, InitializeCriticalSection,
        LeaveCriticalSection, SetThreadpoolTimer, RTL_CRITICAL_SECTION, TP_CALLBACK_ENVIRON_V3,
        TP_CALLBACK_INSTANCE, TP_TIMER,
    },
};

#[cfg(target_os = "linux")]
use crate::bolts::current_time;
#[cfg(all(windows, feature = "std"))]
use crate::executors::inprocess::HasInProcessHandlers;
#[cfg(any(windows, target_os = "linux"))]
use crate::executors::inprocess::GLOBAL_STATE;
use crate::{
    executors::{inprocess::InProcessExecutorHandlerData, Executor, ExitKind, HasObservers},
    observers::UsesObservers,
    state::UsesState,
    Error,
};

#[repr(C)]
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[cfg(all(unix, not(target_os = "linux")))]
impl Debug for Timeval {
    #[allow(clippy::cast_sign_loss)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Timeval {{ tv_sec: {:?}, tv_usec: {:?} (tv: {:?}) }}",
            self.tv_sec,
            self.tv_usec,
            Duration::new(self.tv_sec as _, (self.tv_usec * 1000) as _)
        )
    }
}

#[repr(C)]
#[cfg(all(unix, not(target_os = "linux")))]
#[derive(Debug)]
pub(crate) struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

#[cfg(all(unix, not(target_os = "linux")))]
extern "C" {
    fn setitimer(which: c_int, new_value: *mut Itimerval, old_value: *mut Itimerval) -> c_int;
}

#[cfg(all(unix, not(target_os = "linux")))]
const ITIMER_REAL: c_int = 0;

/// The timeout executor is a wrapper that sets a timeout before each run
pub struct TimeoutExecutor<E> {
    /// The wrapped [`Executor`]
    executor: E,
    #[cfg(target_os = "linux")]
    itimerspec: libc::itimerspec,
    #[cfg(target_os = "linux")]
    timerid: libc::timer_t,
    #[cfg(all(unix, not(target_os = "linux")))]
    itimerval: Itimerval,
    #[cfg(windows)]
    milli_sec: i64,
    #[cfg(windows)]
    tp_timer: *mut TP_TIMER,
    #[cfg(windows)]
    critical: RTL_CRITICAL_SECTION,

    exec_tmout: Duration,

    // for batch mode (linux only atm)
    #[allow(unused)]
    batch_mode: bool,
    #[allow(unused)]
    executions: u32,
    #[allow(unused)]
    avg_mul_k: u32,
    #[allow(unused)]
    last_signal_time: Duration,
    #[allow(unused)]
    avg_exec_time: Duration,
    #[allow(unused)]
    start_time: Duration,
    #[allow(unused)]
    tmout_start_time: Duration,
}

impl<E: Debug> Debug for TimeoutExecutor<E> {
    #[cfg(windows)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutExecutor")
            .field("executor", &self.executor)
            .field("milli_sec", &self.milli_sec)
            .finish_non_exhaustive()
    }

    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutExecutor")
            .field("executor", &self.executor)
            .field(
                "milli_sec",
                &(&self.itimerspec.it_value.tv_sec * 1000
                    + &self.itimerspec.it_value.tv_nsec / 1000 / 1000),
            )
            .finish()
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutExecutor")
            .field("executor", &self.executor)
            .field("itimerval", &self.itimerval)
            .finish()
    }
}

#[cfg(windows)]
#[allow(non_camel_case_types)]
type PTP_TIMER_CALLBACK = unsafe extern "system" fn(
    param0: *mut TP_CALLBACK_INSTANCE,
    param1: *mut c_void,
    param2: *mut TP_TIMER,
);

#[cfg(target_os = "linux")]
impl<E> TimeoutExecutor<E> {
    /// Create a new [`TimeoutExecutor`], wrapping the given `executor` and checking for timeouts.
    /// This should usually be used for `InProcess` fuzzing.
    pub fn new(executor: E, exec_tmout: Duration) -> Self {
        let milli_sec = exec_tmout.as_millis();
        let it_value = libc::timespec {
            tv_sec: (milli_sec / 1000) as _,
            tv_nsec: ((milli_sec % 1000) * 1000 * 1000) as _,
        };
        let it_interval = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let itimerspec = libc::itimerspec {
            it_interval,
            it_value,
        };
        let mut timerid: libc::timer_t = null_mut();
        unsafe {
            // creates a new per-process interval timer
            libc::timer_create(libc::CLOCK_MONOTONIC, null_mut(), addr_of_mut!(timerid));
        }
        Self {
            executor,
            itimerspec,
            timerid,
            exec_tmout,
            batch_mode: false,
            executions: 0,
            avg_mul_k: 1,
            last_signal_time: Duration::ZERO,
            avg_exec_time: Duration::ZERO,
            start_time: Duration::ZERO,
            tmout_start_time: Duration::ZERO,
        }
    }

    /// Create a new [`TimeoutExecutor`], wrapping the given `executor` and checking for timeouts.
    /// With this method batch mode is enabled.
    pub fn batch_mode(executor: E, exec_tmout: Duration) -> Self {
        let mut me = Self::new(executor, exec_tmout);
        me.batch_mode = true;
        me
    }

    /// Set the timeout for this executor
    pub fn set_timeout(&mut self, exec_tmout: Duration) {
        let milli_sec = exec_tmout.as_millis();
        let it_value = libc::timespec {
            tv_sec: (milli_sec / 1000) as _,
            tv_nsec: ((milli_sec % 1000) * 1000 * 1000) as _,
        };
        let it_interval = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let itimerspec = libc::itimerspec {
            it_interval,
            it_value,
        };
        self.itimerspec = itimerspec;
        self.exec_tmout = exec_tmout;
    }

    pub(crate) fn handle_timeout(&mut self, data: &mut InProcessExecutorHandlerData) -> bool {
        if !self.batch_mode {
            return false;
        }
        // eprintln!("handle_timeout {:?} {}", self.avg_exec_time, self.avg_mul_k);
        let cur_time = current_time();
        if !data.is_valid() {
            // outside the target
            unsafe {
                let disarmed: libc::itimerspec = zeroed();
                libc::timer_settime(self.timerid, 0, addr_of!(disarmed), null_mut());
            }
            let elapsed = cur_time - self.tmout_start_time;
            // set timer the next exec
            if self.executions > 0 {
                self.avg_exec_time = elapsed / self.executions;
                self.executions = 0;
            }
            self.avg_mul_k += 1;
            self.last_signal_time = cur_time;
            return true;
        }

        let elapsed_run = cur_time - self.start_time;
        if elapsed_run < self.exec_tmout {
            // fp, reset timeout
            unsafe {
                libc::timer_settime(self.timerid, 0, addr_of!(self.itimerspec), null_mut());
            }
            if self.executions > 0 {
                let elapsed = cur_time - self.tmout_start_time;
                self.avg_exec_time = elapsed / self.executions;
                self.executions = 0; // It will be 1 when the exec finish
            }
            self.tmout_start_time = current_time();
            self.avg_mul_k += 1;
            self.last_signal_time = cur_time;
            true
        } else {
            false
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
impl<E> TimeoutExecutor<E> {
    /// Create a new [`TimeoutExecutor`], wrapping the given `executor` and checking for timeouts.
    /// This should usually be used for `InProcess` fuzzing.
    pub fn new(executor: E, exec_tmout: Duration) -> Self {
        let milli_sec = exec_tmout.as_millis();
        let it_value = Timeval {
            tv_sec: (milli_sec / 1000) as i64,
            tv_usec: (milli_sec % 1000) as i64,
        };
        let it_interval = Timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let itimerval = Itimerval {
            it_interval,
            it_value,
        };
        Self {
            executor,
            itimerval,
            exec_tmout,
            batch_mode: false,
            executions: 0,
            avg_mul_k: 1,
            last_signal_time: Duration::ZERO,
            avg_exec_time: Duration::ZERO,
            start_time: Duration::ZERO,
            tmout_start_time: Duration::ZERO,
        }
    }

    /// Set the timeout for this executor
    pub fn set_timeout(&mut self, exec_tmout: Duration) {
        let milli_sec = exec_tmout.as_millis();
        let it_value = Timeval {
            tv_sec: (milli_sec / 1000) as i64,
            tv_usec: (milli_sec % 1000) as i64,
        };
        let it_interval = Timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let itimerval = Itimerval {
            it_interval,
            it_value,
        };
        self.itimerval = itimerval;
        self.exec_tmout = exec_tmout;
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn handle_timeout(&mut self, _data: &mut InProcessExecutorHandlerData) -> bool {
        false // TODO
    }
}

#[cfg(windows)]
impl<E: HasInProcessHandlers> TimeoutExecutor<E> {
    /// Create a new [`TimeoutExecutor`], wrapping the given `executor` and checking for timeouts.
    pub fn new(executor: E, exec_tmout: Duration) -> Self {
        let milli_sec = exec_tmout.as_millis() as i64;
        let timeout_handler: PTP_TIMER_CALLBACK =
            unsafe { std::mem::transmute(executor.inprocess_handlers().timeout_handler) };
        let tp_timer = unsafe {
            CreateThreadpoolTimer(
                Some(timeout_handler),
                Some(addr_of_mut!(GLOBAL_STATE) as *mut c_void),
                Some(&TP_CALLBACK_ENVIRON_V3::default()),
            )
        };
        let mut critical = RTL_CRITICAL_SECTION::default();

        unsafe {
            InitializeCriticalSection(&mut critical);
        }

        Self {
            executor,
            milli_sec,
            tp_timer,
            critical,
            exec_tmout,
            batch_mode: false,
            executions: 0,
            avg_mul_k: 1,
            last_signal_time: Duration::ZERO,
            avg_exec_time: Duration::ZERO,
            start_time: Duration::ZERO,
            tmout_start_time: Duration::ZERO,
        }
    }

    /// Set the timeout for this executor
    pub fn set_timeout(&mut self, exec_tmout: Duration) {
        self.milli_sec = exec_tmout.as_millis() as i64;
        self.exec_tmout = exec_tmout;
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn handle_timeout(&mut self, _data: &mut InProcessExecutorHandlerData) -> bool {
        false // TODO
    }

    /// Retrieve the inner `Executor` that is wrapped by this `TimeoutExecutor`.
    pub fn inner(&mut self) -> &mut E {
        &mut self.executor
    }
}

#[cfg(windows)]
impl<E, EM, Z> Executor<EM, Z> for TimeoutExecutor<E>
where
    E: Executor<EM, Z> + HasInProcessHandlers,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    #[allow(clippy::cast_sign_loss)]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        unsafe {
            let data = &mut GLOBAL_STATE;
            write_volatile(
                &mut data.timeout_executor_ptr,
                self as *mut _ as *mut c_void,
            );

            write_volatile(&mut data.tp_timer, self.tp_timer as *mut _ as *mut c_void);
            write_volatile(
                &mut data.critical,
                addr_of_mut!(self.critical) as *mut c_void,
            );
            write_volatile(
                &mut data.timeout_input_ptr,
                addr_of_mut!(data.current_input_ptr) as *mut c_void,
            );
            let tm: i64 = -self.milli_sec * 10 * 1000;
            let ft = FILETIME {
                dwLowDateTime: (tm & 0xffffffff) as u32,
                dwHighDateTime: (tm >> 32) as u32,
            };

            compiler_fence(Ordering::SeqCst);
            EnterCriticalSection(&mut self.critical);
            compiler_fence(Ordering::SeqCst);
            data.in_target = 1;
            compiler_fence(Ordering::SeqCst);
            LeaveCriticalSection(&mut self.critical);
            compiler_fence(Ordering::SeqCst);

            SetThreadpoolTimer(self.tp_timer, Some(&ft), 0, 0);

            let ret = self.executor.run_target(fuzzer, state, mgr, input);

            compiler_fence(Ordering::SeqCst);
            EnterCriticalSection(&mut self.critical);
            compiler_fence(Ordering::SeqCst);
            // Timeout handler will do nothing after we increment in_target value.
            data.in_target = 0;
            compiler_fence(Ordering::SeqCst);
            LeaveCriticalSection(&mut self.critical);
            compiler_fence(Ordering::SeqCst);

            write_volatile(&mut data.timeout_input_ptr, core::ptr::null_mut());

            self.post_run_reset();
            ret
        }
    }

    /// Deletes this timer queue
    /// # Safety
    /// Will dereference the given `tp_timer` pointer, unchecked.
    fn post_run_reset(&mut self) {
        unsafe {
            SetThreadpoolTimer(self.tp_timer, None, 0, 0);
        }
        self.executor.post_run_reset();
    }
}

#[cfg(target_os = "linux")]
impl<E, EM, Z> Executor<EM, Z> for TimeoutExecutor<E>
where
    E: Executor<EM, Z>,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        unsafe {
            if self.batch_mode {
                let data = &mut GLOBAL_STATE;
                write_volatile(
                    &mut data.timeout_executor_ptr,
                    self as *mut _ as *mut c_void,
                );

                if self.executions == 0 {
                    libc::timer_settime(self.timerid, 0, addr_of_mut!(self.itimerspec), null_mut());
                    self.tmout_start_time = current_time();
                }
                self.start_time = current_time();
            } else {
                libc::timer_settime(self.timerid, 0, addr_of_mut!(self.itimerspec), null_mut());
            }

            let ret = self.executor.run_target(fuzzer, state, mgr, input);
            // reset timer
            self.post_run_reset();
            ret
        }
    }

    fn post_run_reset(&mut self) {
        if self.batch_mode {
            unsafe {
                let elapsed = current_time() - self.tmout_start_time;
                // elapsed may be > than tmout in case of reveived but ingored signal
                if elapsed > self.exec_tmout
                    || self.exec_tmout - elapsed < self.avg_exec_time * self.avg_mul_k
                {
                    let disarmed: libc::itimerspec = zeroed();
                    libc::timer_settime(self.timerid, 0, addr_of!(disarmed), null_mut());
                    // set timer the next exec
                    if self.executions > 0 {
                        self.avg_exec_time = elapsed / self.executions;
                        self.executions = 0;
                    }
                    // readjust K
                    if self.last_signal_time > self.exec_tmout * self.avg_mul_k
                        && self.avg_mul_k > 1
                    {
                        self.avg_mul_k -= 1;
                    }
                } else {
                    self.executions += 1;
                }
            }
        } else {
            unsafe {
                let disarmed: libc::itimerspec = zeroed();
                libc::timer_settime(self.timerid, 0, addr_of!(disarmed), null_mut());
            }
        }
        self.executor.post_run_reset();
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
impl<E, EM, Z> Executor<EM, Z> for TimeoutExecutor<E>
where
    E: Executor<EM, Z>,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        unsafe {
            setitimer(ITIMER_REAL, &mut self.itimerval, null_mut());
            let ret = self.executor.run_target(fuzzer, state, mgr, input);
            self.post_run_reset();
            ret
        }
    }

    fn post_run_reset(&mut self) {
        unsafe {
            let mut itimerval_zero: Itimerval = zeroed();
            setitimer(ITIMER_REAL, &mut itimerval_zero, null_mut());
        }
        self.executor.post_run_reset();
    }
}

impl<E> UsesState for TimeoutExecutor<E>
where
    E: UsesState,
{
    type State = E::State;
}

impl<E> UsesObservers for TimeoutExecutor<E>
where
    E: UsesObservers,
{
    type Observers = E::Observers;
}

impl<E> HasObservers for TimeoutExecutor<E>
where
    E: HasObservers,
{
    #[inline]
    fn observers(&self) -> &Self::Observers {
        self.executor.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut Self::Observers {
        self.executor.observers_mut()
    }
}
