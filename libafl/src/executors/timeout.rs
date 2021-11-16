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
use crate::executors::inprocess::GLOBAL_STATE;

#[cfg(all(windows, feature = "std"))]
use crate::bolts::os::windows_exceptions::ExceptionCode;

#[cfg(unix)]
use core::{mem::zeroed, ptr::null_mut};
#[cfg(unix)]
use libc::c_int;

#[cfg(all(windows, feature = "std"))]
use windows::Win32::{
    Foundation::FILETIME,
    System::Diagnostics::Debug::RaiseException,
    System::Threading::{
        CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, TP_CALLBACK_ENVIRON_V3,
        TP_TIMER,
    },
};

#[cfg(all(windows, feature = "std"))]
use core::{ffi::c_void, ptr::write_volatile};

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
pub fn unix_remove_timeout() {
    unsafe {
        let mut itimerval_zero: Itimerval = zeroed();
        setitimer(ITIMER_REAL, &mut itimerval_zero, null_mut());
    }
}

/// The timeout excutor is a wrapper that sets a timeout before each run
pub struct TimeoutExecutor<E> {
    executor: E,
    #[cfg(unix)]
    itimerval: Itimerval,
    #[cfg(windows)]
    exec_tmout: Duration,
}

impl<E> TimeoutExecutor<E> {
    /// Create a new `TimeoutExecutor`, wrapping the given `executor` and checking for timeouts.
    /// This should usually be used for `InProcess` fuzzing.
    #[cfg(unix)]
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

    #[cfg(windows)]
    pub fn new(executor: E, exec_tmout: Duration) -> Self {
        Self {
            executor,
            exec_tmout,
        }
    }

    /// Retrieve the inner `Executor` that is wrapped by this `TimeoutExecutor`.
    pub fn inner(&mut self) -> &mut E {
        &mut self.executor
    }
}

#[cfg(windows)]
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
            let data = &mut GLOBAL_STATE;
            write_volatile(
                &mut data.timeout_input_ptr,
                input as *const _ as *mut c_void,
            );
            let before = crate::bolts::current_time();
            let ret = self.executor.run_target(fuzzer, state, mgr, input);
            let after = crate::bolts::current_time();
            if after - before > self.exec_tmout {
                RaiseException(ExceptionCode::Timeout as u32, 0, 0, core::ptr::null());
            }
            write_volatile(&mut data.timeout_input_ptr, core::ptr::null_mut());
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
