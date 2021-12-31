//! A `TimeoutExecutor` sets a timeout before each target run

#[cfg(any(windows, unix))]
use core::time::Duration;

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
#[cfg(unix)]
use libc::c_int;

#[cfg(all(windows, feature = "std"))]
use windows::Win32::{
    Foundation::FILETIME,
    System::Threading::{
        CloseThreadpoolTimer, CreateThreadpoolTimer, EnterCriticalSection,
        InitializeCriticalSection, LeaveCriticalSection, SetThreadpoolTimer, RTL_CRITICAL_SECTION,
        TP_CALLBACK_ENVIRON_V3, TP_CALLBACK_INSTANCE, TP_TIMER,
    },
};

#[cfg(all(windows, feature = "std"))]
use core::{ffi::c_void, ptr::write_volatile};

#[cfg(windows)]
use core::sync::atomic::{compiler_fence, Ordering};

#[repr(C)]
#[cfg(unix)]
struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[cfg(unix)]
struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

#[cfg(unix)]
extern "C" {
    fn setitimer(which: c_int, new_value: *mut Itimerval, old_value: *mut Itimerval) -> c_int;
}

#[cfg(unix)]
const ITIMER_REAL: c_int = 0;

/// Reset and remove the timeout
#[cfg(unix)]
pub(crate) fn unix_remove_timeout() {
    unsafe {
        let mut itimerval_zero: Itimerval = zeroed();
        setitimer(ITIMER_REAL, &mut itimerval_zero, null_mut());
    }
}

/// Deletes this timer queue
/// # Safety
/// Will dereference the given `tp_timer` pointer, unchecked.
#[cfg(all(windows, feature = "std"))]
pub(crate) unsafe fn windows_delete_timer_queue(tp_timer: *mut TP_TIMER) {
    CloseThreadpoolTimer(tp_timer);
}

/// The timeout excutor is a wrapper that sets a timeout before each run
#[allow(missing_debug_implementations)]
pub struct TimeoutExecutor<E> {
    executor: E,
    #[cfg(unix)]
    itimerval: Itimerval,
    #[cfg(windows)]
    milli_sec: i64,
    #[cfg(windows)]
    tp_timer: *mut TP_TIMER,
    #[cfg(windows)]
    critical: RTL_CRITICAL_SECTION,
}

#[cfg(windows)]
#[allow(non_camel_case_types)]
type PTP_TIMER_CALLBACK = unsafe extern "system" fn(
    param0: *mut TP_CALLBACK_INSTANCE,
    param1: *mut c_void,
    param2: *mut TP_TIMER,
);

#[cfg(unix)]
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
                &mut GLOBAL_STATE as *mut _ as *mut c_void,
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
    #[cfg(unix)]
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

    /// Set the timeout for this executor
    #[cfg(windows)]
    pub fn set_timeout(&mut self, exec_tmout: Duration) {
        self.milli_sec = exec_tmout.as_millis() as i64;
    }

    /// Retrieve the inner `Executor` that is wrapped by this `TimeoutExecutor`.
    pub fn inner(&mut self) -> &mut E {
        &mut self.executor
    }

    /// Reset the timeout for this executor
    #[cfg(windows)]
    pub fn windows_reset_timeout(&self) -> Result<(), Error> {
        unsafe {
            SetThreadpoolTimer(self.tp_timer, core::ptr::null(), 0, 0);
        }
        Ok(())
    }
}

#[cfg(windows)]
impl<E, EM, I, S, Z> Executor<EM, I, S, Z> for TimeoutExecutor<E>
where
    E: Executor<EM, I, S, Z> + HasInProcessHandlers,
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
            let data = &mut GLOBAL_STATE;
            write_volatile(&mut data.tp_timer, self.tp_timer as *mut _ as *mut c_void);
            write_volatile(
                &mut data.critical,
                &mut self.critical as *mut _ as *mut c_void,
            );
            write_volatile(
                &mut data.timeout_input_ptr,
                &mut data.current_input_ptr as *mut _ as *mut c_void,
            );
            let tm: i64 = -1 * self.milli_sec * 10 * 1000;
            let mut ft = FILETIME::default();
            ft.dwLowDateTime = (tm & 0xffffffff) as u32;
            ft.dwHighDateTime = (tm >> 32) as u32;

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

            self.windows_reset_timeout()?;
            ret
        }
    }
}

#[cfg(unix)]
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
        #[cfg(unix)]
        unsafe {
            setitimer(ITIMER_REAL, &mut self.itimerval, null_mut());
            let ret = self.executor.run_target(fuzzer, state, mgr, input);
            unix_remove_timeout();
            ret
        }
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

#[cfg(windows)]
impl<E> Drop for TimeoutExecutor<E> {
    fn drop(&mut self) {
        unsafe {
            windows_delete_timer_queue(self.tp_timer);
        }
    }
}
