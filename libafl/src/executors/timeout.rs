//! A `TimeoutExecutor` sets a timeout before each target run

use core::{marker::PhantomData, time::Duration};

use crate::{
    bolts::tuples::Named,
    events::EventManager,
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, Input},
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
pub struct TimeoutExecutor<E, I, OT>
where
    E: Executor<I> + HasObservers<OT>,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    executor: E,
    exec_tmout: Duration,
    phantom: PhantomData<(I, OT)>,
}

impl<E, I, OT> Named for TimeoutExecutor<E, I, OT>
where
    E: Executor<I> + HasObservers<OT>,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        self.executor.name()
    }
}

impl<E, I, OT> HasObservers<OT> for TimeoutExecutor<E, I, OT>
where
    E: Executor<I> + HasObservers<OT>,
    I: Input + HasTargetBytes,
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

impl<E, I, OT> TimeoutExecutor<E, I, OT>
where
    E: Executor<I> + HasObservers<OT>,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(executor: E, exec_tmout: Duration) -> Self {
        Self {
            executor,
            exec_tmout,
            phantom: PhantomData,
        }
    }

    pub fn inner(&mut self) -> &mut E {
        &mut self.executor
    }
}

impl<E, I, OT> Executor<I> for TimeoutExecutor<E, I, OT>
where
    E: Executor<I> + HasObservers<OT>,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn pre_exec<EM: EventManager<I, S>, S>(
        &mut self,
        _state: &mut S,
        _event_mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
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
        self.executor.pre_exec(_state, _event_mgr, _input)
    }

    #[inline]
    fn post_exec<EM: EventManager<I, S>, S>(
        &mut self,
        _state: &mut S,
        _event_mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
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
        self.executor.post_exec(_state, _event_mgr, _input)
    }

    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        self.executor.run_target(input)
    }
}
