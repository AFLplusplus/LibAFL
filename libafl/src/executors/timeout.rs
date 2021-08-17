//! A `TimeoutExecutor` sets a timeout before each target run

#[cfg(any(windows, unix))]
use core::time::Duration;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

#[cfg(windows)]
use crate::executors::inprocess::{InProcessExecutorHandlerData, GLOBAL_STATE};

use core::{mem::zeroed, ptr::null_mut};
#[cfg(unix)]
use libc::c_int;

#[cfg(windows)]
use crate::bolts::bindings::Windows::Win32::{
    Foundation::HANDLE,
    System::Threading::{
        CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueTimer, WORKER_THREAD_FLAGS,
    },
};

#[cfg(windows)]
use core::ffi::c_void;

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

unsafe extern "system" fn wintimer_handler<I>(gloabl_state: *mut c_void, _p1: u8)
where
    I: Input,
{
    let data: &mut InProcessExecutorHandlerData =
        unsafe { &mut *(gloabl_state as *mut InProcessExecutorHandlerData) };
    let input = (data.current_input_ptr as *const I).as_ref().unwrap();
    println!("input: {:#?}", input);
    println!("TIMER INVOKED!");
}

/// The timeout excutor is a wrapper that sets a timeout before each run
pub struct TimeoutExecutor<E> {
    executor: E,
    #[cfg(unix)]
    itimerval: Itimerval,
    #[cfg(windows)]
    milli_sec: u32,
    #[cfg(windows)]
    ph_new_timer: HANDLE,
    #[cfg(windows)]
    timer_queue: HANDLE,
}

impl<E> TimeoutExecutor<E> {
    /// Create a new `TimeoutExecutor`, wrapping the given `executor` and checking for timeouts.
    /// This should usually be used for `InProcess` fuzzing.
    #[cfg(unix)]
    pub fn new(executor: E, exec_tmout: Duration) -> Result<Self, Error> {
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
        Ok(Self {
            executor,
            itimerval,
        })
    }

    #[cfg(windows)]
    pub unsafe fn new(executor: E, exec_tmout: Duration) -> Result<Self, Error> {
        let milli_sec = exec_tmout.as_millis() as u32;
        let timer_queue = CreateTimerQueue();
        if timer_queue == HANDLE::NULL {
            return Err(Error::Unknown("CreateTimerQueue failed.".to_string()));
        }
        let ph_new_timer = HANDLE::NULL;
        Ok(Self {
            executor,
            milli_sec,
            ph_new_timer,
            timer_queue,
        })
    }

    /// Retrieve the inner `Executor` that is wrapped by this `TimeoutExecutor`.
    pub fn inner(&mut self) -> &mut E {
        &mut self.executor
    }

    /// Reset and remove the timeout
    #[cfg(unix)]
    pub fn remove_timeout(&self) -> Result<(), Error> {
        unsafe {
            let mut itimerval_zero: Itimerval = zeroed();
            setitimer(ITIMER_REAL, &mut itimerval_zero, null_mut());
        }
        Ok(())
    }

    #[cfg(windows)]
    pub fn remove_timeout(&self) -> Result<(), Error> {
        unsafe {
            let code = DeleteTimerQueueTimer(self.timer_queue, self.ph_new_timer, HANDLE::NULL);
            if !code.as_bool() {
                return Err(Error::Unknown(format!("DeleteTimerQueueTimer failed.")));
            }
        }
        Ok(())
    }
}

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
            self.remove_timeout()?;
            ret
        }
        #[cfg(windows)]
        unsafe {
            let code = CreateTimerQueueTimer(
                &mut self.ph_new_timer,
                &self.timer_queue,
                Some(wintimer_handler::<I>),
                &mut GLOBAL_STATE as *mut _ as *mut c_void,
                self.milli_sec,
                0,
                WORKER_THREAD_FLAGS::default(),
            );
            if !code.as_bool() {
                return Err(Error::Unknown("CreateTimerQueue failed.".to_string()));
            }
            let ret = self.executor.run_target(fuzzer, state, mgr, input);
            self.remove_timeout()?;
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
