//! A `TimeoutExecutor` sets a timeout before each target run

use core::time::Duration;

use crate::{
    executors::{Executor, ExitKind, HasExecHooksTuple, HasObservers, HasObserversHooks},
    inputs::Input,
    observers::ObserversTuple,
    Error,
};

#[cfg(unix)]
use core::ptr::null_mut;
#[cfg(unix)]
use libc::c_int;

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

/// The timeout excutor is a wrapper that set a timeout before each run
pub struct TimeoutExecutor<E> {
    executor: E,
    exec_tmout: Duration,
}

impl<E> TimeoutExecutor<E> {
    /// Create a new `TimeoutExecutor`, wrapping the given `executor` and checking for timeouts.
    /// This should usually be used for `InProcess` fuzzing.
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
            let milli_sec = self.exec_tmout.as_millis();
            let it_value = Timeval {
                tv_sec: (milli_sec / 1000) as i64,
                tv_usec: (milli_sec % 1000) as i64,
            };
            let it_interval = Timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            setitimer(
                ITIMER_REAL,
                &mut Itimerval {
                    it_interval,
                    it_value,
                },
                null_mut(),
            );
        }
        #[cfg(windows)]
        {
            // TODO
            let _ = self.exec_tmout.as_millis();
        }

        let ret = self.executor.run_target(fuzzer, state, mgr, input);

        #[cfg(unix)]
        unsafe {
            let it_value = Timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            let it_interval = Timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            setitimer(
                ITIMER_REAL,
                &mut Itimerval {
                    it_interval,
                    it_value,
                },
                null_mut(),
            );
        }
        #[cfg(windows)]
        {
            // TODO
        }

        ret
    }
}

impl<E, OT> HasObservers<OT> for TimeoutExecutor<E>
where
    E: HasObservers<OT>,
    OT: ObserversTuple,
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

impl<E, EM, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z> for TimeoutExecutor<E>
where
    E: HasObservers<OT>,
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}
