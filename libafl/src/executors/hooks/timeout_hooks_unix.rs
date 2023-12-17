use std::time::Duration;
use core::{fmt::{self, Debug, Formatter}, ptr::{null_mut, addr_of_mut, addr_of}, mem::zeroed};
use libafl_bolts::current_time;
use crate::executors::hooks::inprocess_hooks_unix::DefaultExecutorHooksData;

/// Set the timer with this hook
#[cfg(unix)]
pub struct TimeoutExecutorHooks {
    #[cfg(target_os = "linux")]
    itimerspec: libc::itimerspec,
    #[cfg(target_os = "linux")]
    timerid: libc::timer_t,
    #[cfg(all(unix, not(target_os = "linux")))]
    itimerval: Itimerval,

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

impl Debug for TimeoutExecutorHooks {
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutExecutor")
            .field(
                "milli_sec",
                &(&self.itimerspec.it_value.tv_sec * 1000
                    + &self.itimerspec.it_value.tv_nsec / 1000 / 1000),
            )
            .finish_non_exhaustive()
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutExecutor")
            .field("executor", &self.executor)
            .field("itimerval", &self.itimerval)
            .finish_non_exhaustive()
    }
}

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

#[cfg(target_os = "linux")]
impl TimeoutExecutorHooks {
    /// Create a new [`TimeoutExecutorHooks`]
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
            // creates a new per-process interval timer
            libc::timer_create(libc::CLOCK_MONOTONIC, null_mut(), addr_of_mut!(timerid));
        }
        Self {
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

    /// Create a new [`TimeoutExecutorHooks`]
    /// With this method batch mode is enabled.
    pub fn batch_mode(exec_tmout: Duration) -> Self {
        let mut me = Self::new(exec_tmout);
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

    pub(crate) fn handle_timeout(&mut self, data: &DefaultExecutorHooksData) -> bool {
        if !self.batch_mode {
            return false;
        }
        //eprintln!("handle_timeout {:?} {}", self.avg_exec_time, self.avg_mul_k);
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