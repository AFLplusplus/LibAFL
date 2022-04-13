//! A `TimeoutExecutor` sets a timeout before each target run

#[cfg(any(windows, unix))]
use core::{
    fmt::{self, Debug, Formatter},
    time::Duration,
};

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

#[cfg(all(windows, feature = "std"))]
use crate::executors::inprocess::{HasInProcessHandlers, GLOBAL_STATE};

#[cfg(unix)]
use core::{mem::zeroed, ptr::null_mut};

#[cfg(target_os = "linux")]
use core::ptr::{addr_of, addr_of_mut};

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

#[cfg(all(windows, feature = "std"))]
use core::{ffi::c_void, ptr::write_volatile};

#[cfg(windows)]
use core::sync::atomic::{compiler_fence, Ordering};

#[repr(C)]
#[cfg(all(unix, not(target_os = "linux")))]
struct Timeval {
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
struct Itimerval {
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
        }
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
                core::ptr::addr_of_mut!(GLOBAL_STATE) as *mut c_void,
                &TP_CALLBACK_ENVIRON_V3::default(),
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
        }
    }

    /// Set the timeout for this executor
    #[cfg(windows)]
    pub fn set_timeout(&mut self, exec_tmout: Duration) {
        self.milli_sec = exec_tmout.as_millis() as i64;
    }

    /// Retrieve the inner `Executor` that is wrapped by this `TimeoutExecutor`.
    pub fn inner(&mut self) -> &mut E {
        &mut self.executor
    }
}

#[cfg(windows)]
impl<E, EM, I, S, Z> Executor<EM, I, S, Z> for TimeoutExecutor<E>
where
    E: Executor<EM, I, S, Z> + HasInProcessHandlers,
    I: Input,
{
    #[allow(clippy::cast_sign_loss)]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        unsafe {
            let data = &mut GLOBAL_STATE;
            write_volatile(&mut data.tp_timer, self.tp_timer as *mut _ as *mut c_void);
            write_volatile(
                &mut data.critical,
                core::ptr::addr_of_mut!(self.critical) as *mut c_void,
            );
            write_volatile(
                &mut data.timeout_input_ptr,
                data.current_input_ptr as *mut c_void,
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

            SetThreadpoolTimer(self.tp_timer, &ft, 0, 0);

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
            SetThreadpoolTimer(self.tp_timer, core::ptr::null(), 0, 0);
        }
        self.executor.post_run_reset();
    }
}

#[cfg(target_os = "linux")]
impl<E, EM, I, S, Z> Executor<EM, I, S, Z> for TimeoutExecutor<E>
where
    E: Executor<EM, I, S, Z>,
    I: Input,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        unsafe {
            libc::timer_settime(self.timerid, 0, addr_of_mut!(self.itimerspec), null_mut());
            let ret = self.executor.run_target(fuzzer, state, mgr, input);
            // reset timer
            self.post_run_reset();
            ret
        }
    }

    fn post_run_reset(&mut self) {
        unsafe {
            let disarmed: libc::itimerspec = zeroed();
            libc::timer_settime(self.timerid, 0, addr_of!(disarmed), null_mut());
        }
        self.executor.post_run_reset();
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
impl<E, EM, I, S, Z> Executor<EM, I, S, Z> for TimeoutExecutor<E>
where
    E: Executor<EM, I, S, Z>,
    I: Input,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
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

impl<E, I, OT, S> HasObservers<I, OT, S> for TimeoutExecutor<E>
where
    E: HasObservers<I, OT, S>,
    OT: ObserversTuple<I, S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.executor.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.executor.observers_mut()
    }
}
