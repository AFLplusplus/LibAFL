use core::time::Duration;
#[cfg(any(all(feature = "std", windows), target_os = "linux"))]
use core::{
    ffi::c_void,
    ptr::{addr_of_mut, write_volatile},
};
#[cfg(target_os = "linux")]
use core::{
    mem::zeroed,
    ptr::{addr_of, null_mut},
};

#[cfg(all(unix, not(target_os = "linux")))]
const ITIMER_REAL: core::ffi::c_int = 0;

#[cfg(target_os = "linux")]
use libafl_bolts::current_time;
#[cfg(all(feature = "std", windows))]
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(all(windows, feature = "std"))]
use windows::Win32::{
    Foundation::FILETIME,
    System::Threading::{
        EnterCriticalSection, LeaveCriticalSection, SetThreadpoolTimer, CRITICAL_SECTION, PTP_TIMER,
    },
};

use crate::executors::hooks::inprocess::GLOBAL_STATE;

#[repr(C)]
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[cfg(all(unix, not(target_os = "linux")))]
impl core::fmt::Debug for Timeval {
    #[allow(clippy::cast_sign_loss)]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

/// The strcut about all the internals of the timer.
/// This struct absorb all platform specific differences about timer.
#[allow(missing_debug_implementations)]
pub struct TimerStruct {
    // timeout time (windows)
    #[cfg(all(windows, feature = "std"))]
    milli_sec: i64,
    #[cfg(all(windows, feature = "std"))]
    ptp_timer: PTP_TIMER,
    #[cfg(all(windows, feature = "std"))]
    critical: CRITICAL_SECTION,
    #[cfg(unix)]
    pub(crate) batch_mode: bool,
    #[cfg(unix)]
    pub(crate) exec_tmout: Duration,
    #[cfg(target_os = "linux")]
    pub(crate) timerid: libc::timer_t,
    #[cfg(target_os = "linux")]
    pub(crate) itimerspec: libc::itimerspec,
    #[cfg(unix)]
    pub(crate) executions: u32,
    #[cfg(unix)]
    pub(crate) avg_mul_k: u32,
    #[cfg(unix)]
    pub(crate) last_signal_time: Duration,
    #[cfg(unix)]
    pub(crate) avg_exec_time: Duration,
    #[cfg(unix)]
    pub(crate) start_time: Duration,
    #[cfg(unix)]
    pub(crate) tmout_start_time: Duration,
}

impl TimerStruct {
    #[cfg(all(windows, feature = "std"))]
    /// Timeout value in milli seconds
    pub fn milli_sec(&self) -> i64 {
        self.milli_sec
    }

    #[cfg(all(windows, feature = "std"))]
    /// Timeout value in milli seconds (mut ref)
    pub fn milli_sec_mut(&mut self) -> &mut i64 {
        &mut self.milli_sec
    }

    #[cfg(all(windows, feature = "std"))]
    /// The timer object for windows
    pub fn ptp_timer(&self) -> &PTP_TIMER {
        &self.ptp_timer
    }

    #[cfg(all(windows, feature = "std"))]
    /// The timer object for windows
    pub fn ptp_timer_mut(&mut self) -> &mut PTP_TIMER {
        &mut self.ptp_timer
    }

    #[cfg(all(windows, feature = "std"))]
    /// The critical section, we need to use critical section to access the globals
    pub fn critical(&self) -> &CRITICAL_SECTION {
        &self.critical
    }

    #[cfg(all(windows, feature = "std"))]
    /// The critical section (mut ref), we need to use critical section to access the globals
    pub fn critical_mut(&mut self) -> &mut CRITICAL_SECTION {
        &mut self.critical
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn new(exec_tmout: Duration) -> Self {
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

    #[cfg(windows)]
    /// Constructor
    pub fn new(exec_tmout: Duration) -> Self {
        let milli_sec = exec_tmout.as_millis() as i64;
        Self {
            ptp_timer: PTP_TIMER::default(),
            milli_sec,
            critical: CRITICAL_SECTION::default(),
        }
    }

    #[cfg(target_os = "linux")]
    #[must_use]
    #[allow(unused_unsafe)]
    #[allow(unused_mut)]
    /// Constructor for linux
    pub fn new(exec_tmout: Duration) -> Self {
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
            #[cfg(not(miri))]
            // creates a new per-process interval timer
            libc::timer_create(libc::CLOCK_MONOTONIC, null_mut(), addr_of_mut!(timerid));
        }

        Self {
            batch_mode: false,
            itimerspec,
            timerid,
            exec_tmout,
            executions: 0,
            avg_mul_k: 1,
            last_signal_time: Duration::ZERO,
            avg_exec_time: Duration::ZERO,
            start_time: Duration::ZERO,
            tmout_start_time: Duration::ZERO,
        }
    }

    #[cfg(target_os = "linux")]
    #[must_use]
    /// Constructor but batch mode
    pub fn batch_mode(exec_tmout: Duration) -> Self {
        let mut me = Self::new(exec_tmout);
        me.batch_mode = true;
        me
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn set_timer(&mut self) {
        libc::setitimer(ITIMER_REAL, &mut self.itimerval, core::ptr::null_mut());
    }

    #[cfg(all(windows, feature = "std"))]
    /// Set timer
    pub fn set_timer(&mut self) {
        unsafe {
            let data = &mut GLOBAL_STATE;

            write_volatile(&mut data.ptp_timer, Some(*self.ptp_timer()));
            write_volatile(
                &mut data.critical,
                addr_of_mut!(*self.critical_mut()) as *mut c_void,
            );
            let tm: i64 = -self.milli_sec() * 10 * 1000;
            let ft = FILETIME {
                dwLowDateTime: (tm & 0xffffffff) as u32,
                dwHighDateTime: (tm >> 32) as u32,
            };

            // enter critical section then set timer
            compiler_fence(Ordering::SeqCst);
            EnterCriticalSection(self.critical_mut());
            compiler_fence(Ordering::SeqCst);
            data.in_target = 1;
            compiler_fence(Ordering::SeqCst);
            LeaveCriticalSection(self.critical_mut());
            compiler_fence(Ordering::SeqCst);

            SetThreadpoolTimer(*self.ptp_timer(), Some(&ft), 0, 0);
        }
    }

    /// Set up timer
    #[cfg(target_os = "linux")]
    pub fn set_timer(&mut self) {
        unsafe {
            if self.batch_mode {
                let data = &mut GLOBAL_STATE;
                write_volatile(&mut data.executor_ptr, self as *mut _ as *mut c_void);

                if self.executions == 0 {
                    libc::timer_settime(self.timerid, 0, addr_of_mut!(self.itimerspec), null_mut());
                    self.tmout_start_time = current_time();
                }
                self.start_time = current_time();
            } else {
                #[cfg(not(miri))]
                libc::timer_settime(self.timerid, 0, addr_of_mut!(self.itimerspec), null_mut());
            }
        }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn unset_timer(&mut self) {
        unsafe {
            let mut itimerval_zero: Itimerval = core::mem::zeroed();
            libc::ABDAY_4setitimer(ITIMER_REAL, &mut itimerval_zero, core::ptr::null_mut());
        }
    }

    /// Disalarm timer
    #[cfg(target_os = "linux")]
    #[allow(unused_variables)]
    pub fn unset_timer(&mut self) {
        if self.batch_mode {
            unsafe {
                let elapsed = current_time() - self.tmout_start_time;
                // elapsed may be > than tmout in case of received but ingored signal
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
                #[cfg(not(miri))]
                libc::timer_settime(self.timerid, 0, addr_of!(disarmed), null_mut());
            }
        }
    }

    #[cfg(all(windows, feature = "std"))]
    /// Disalarm
    pub fn unset_timer(&mut self) {
        unsafe {
            let data = &mut GLOBAL_STATE;

            compiler_fence(Ordering::SeqCst);
            EnterCriticalSection(self.critical_mut());
            compiler_fence(Ordering::SeqCst);
            // Timeout handler will do nothing after we increment in_target value.
            data.in_target = 0;
            compiler_fence(Ordering::SeqCst);
            LeaveCriticalSection(self.critical_mut());
            compiler_fence(Ordering::SeqCst);

            // previously this wa post_run_reset
            SetThreadpoolTimer(*self.ptp_timer(), None, 0, 0);
        }
    }
}
