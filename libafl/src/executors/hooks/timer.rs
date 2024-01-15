use core::{
    ptr::{addr_of_mut, write_volatile},
    time::Duration,
    sync::atomic::{compiler_fence, Ordering},
    ffi::c_void,
};

#[cfg(all(windows, feature = "std"))]
use windows::Win32::{
    Foundation::FILETIME,
    System::Threading::{
        EnterCriticalSection, LeaveCriticalSection, SetThreadpoolTimer, CRITICAL_SECTION, PTP_TIMER,
    },
};

use crate::executors::hooks::inprocess::GLOBAL_STATE;

#[derive(Debug)]
pub struct TimerStruct {
    // timeout time (windows)
    #[cfg(all(windows, feature = "std"))]
    milli_sec: i64,
    #[cfg(all(windows, feature = "std"))]
    ptp_timer: PTP_TIMER,
    #[cfg(all(windows, feature = "std"))]
    critical: CRITICAL_SECTION,
}

impl TimerStruct {
    #[cfg(all(windows, feature = "std"))]
    pub fn milli_sec(&self) -> i64 {
        self.milli_sec
    }

    #[cfg(all(windows, feature = "std"))]
    pub fn milli_sec_mut(&mut self) -> &mut i64 {
        &mut self.milli_sec
    }

    #[cfg(all(windows, feature = "std"))]
    pub fn ptp_timer(&self) -> &PTP_TIMER {
        &self.ptp_timer
    }

    #[cfg(all(windows, feature = "std"))]
    pub fn ptp_timer_mut(&mut self) -> &mut PTP_TIMER {
        &mut self.ptp_timer
    }

    #[cfg(all(windows, feature = "std"))]
    pub fn critical(&self) -> &CRITICAL_SECTION {
        &self.critical
    }

    #[cfg(all(windows, feature = "std"))]
    pub fn critical_mut(&mut self) -> &mut CRITICAL_SECTION {
        &mut self.critical
    }

    pub fn new(exec_tmout: Duration) -> Self {
        let milli_sec = exec_tmout.as_millis() as i64;
        Self {
            ptp_timer: PTP_TIMER::default(),
            milli_sec,
            critical: CRITICAL_SECTION::default(),
        }
    }

    #[cfg(all(windows, feature = "std"))]
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

    #[cfg(all(windows, feature = "std"))]
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
