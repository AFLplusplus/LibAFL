use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr::{self, null_mut, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};

use libafl_bolts::{
    os::unix_signals::Signal,
    shmem::ShMemProvider,
    tuples::{tuple_list, Merge, RefIndexable},
};
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::Pid,
};

#[cfg(all(unix, not(target_os = "linux")))]
use crate::executors::hooks::timer::{setitimer, Itimerval, Timeval, ITIMER_REAL};
use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::{
            inprocess_fork::{InChildProcessHooks, FORK_EXECUTOR_GLOBAL_DATA},
            ExecutorHooksTuple,
        },
        ExitKind, HasObservers,
    },
    inputs::UsesInput,
    observers::ObserversTuple,
    state::{State, UsesState},
    Error,
};

/// Inner state of GenericInProcessExecutor-like structures.
pub struct GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z> {
    pub(super) hooks: (InChildProcessHooks<S>, HT),
    pub(super) shmem_provider: SP,
    pub(super) observers: OT,
    #[cfg(target_os = "linux")]
    pub(super) itimerspec: libc::itimerspec,
    #[cfg(all(unix, not(target_os = "linux")))]
    pub(super) itimerval: Itimerval,
    pub(super) phantom: PhantomData<(S, EM, Z)>,
}

impl<HT, OT, S, SP, EM, Z> Debug for GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z>
where
    HT: Debug,
    OT: Debug,
    SP: Debug,
{
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessForkExecutorInner")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .field("itimerspec", &self.itimerspec)
            .finish_non_exhaustive()
    }

    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[cfg(not(target_os = "linux"))]
        return f
            .debug_struct("GenericInProcessForkExecutorInner")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .field("itimerval", &self.itimerval)
            .finish_non_exhaustive();
    }
}

impl<HT, OT, S, SP, EM, Z> UsesState for GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z>
where
    S: State,
{
    type State = S;
}

#[cfg(target_os = "linux")]
fn parse_itimerspec(timeout: Duration) -> libc::itimerspec {
    let milli_sec = timeout.as_millis();
    let it_value = libc::timespec {
        tv_sec: (milli_sec / 1000) as _,
        tv_nsec: ((milli_sec % 1000) * 1000 * 1000) as _,
    };
    let it_interval = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    libc::itimerspec {
        it_interval,
        it_value,
    }
}

#[cfg(not(target_os = "linux"))]
fn parse_itimerval(timeout: Duration) -> Itimerval {
    let milli_sec = timeout.as_millis();
    let it_value = Timeval {
        tv_sec: (milli_sec / 1000) as i64,
        tv_usec: (milli_sec % 1000) as i64,
    };
    let it_interval = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    Itimerval {
        it_interval,
        it_value,
    }
}

impl<EM, HT, OT, S, SP, Z> GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z>
where
    OT: ObserversTuple<S::Input, S> + Debug,
    S: State + UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    Z: UsesState<State = S>,
{
    pub(super) unsafe fn pre_run_target_child(
        &mut self,
        fuzzer: &mut Z,
        state: &mut <GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z> as UsesState>::State,
        mgr: &mut EM,
        input: &<GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z> as UsesInput>::Input,
    ) -> Result<(), Error> {
        self.shmem_provider.post_fork(true)?;

        self.enter_target(fuzzer, state, mgr, input);
        self.hooks.pre_exec_all(state, input);

        self.observers
            .pre_exec_child_all(state, input)
            .expect("Failed to run post_exec on observers");

        #[cfg(target_os = "linux")]
        {
            let mut timerid: libc::timer_t = null_mut();
            // creates a new per-process interval timer
            // we can't do this from the parent, timerid is unique to each process.
            libc::timer_create(libc::CLOCK_MONOTONIC, null_mut(), &raw mut timerid);

            // log::info!("Set timer! {:#?} {timerid:#?}", self.itimerspec);
            let _: i32 = libc::timer_settime(timerid, 0, &raw mut self.itimerspec, null_mut());
        }
        #[cfg(not(target_os = "linux"))]
        {
            setitimer(ITIMER_REAL, &mut self.itimerval, null_mut());
        }
        // log::trace!("{v:#?} {}", nix::errno::errno());

        Ok(())
    }

    pub(super) unsafe fn post_run_target_child(
        &mut self,
        fuzzer: &mut Z,
        state: &mut <GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z> as UsesState>::State,
        mgr: &mut EM,
        input: &<GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z> as UsesInput>::Input,
    ) {
        self.observers
            .post_exec_child_all(state, input, &ExitKind::Ok)
            .expect("Failed to run post_exec on observers");

        self.hooks.post_exec_all(state, input);
        self.leave_target(fuzzer, state, mgr, input);

        libc::_exit(0);
    }

    pub(super) fn parent(&mut self, child: Pid) -> Result<ExitKind, Error> {
        // log::trace!("from parent {} child is {}", std::process::id(), child);
        self.shmem_provider.post_fork(false)?;

        let res = waitpid(child, None)?;
        log::trace!("{res:#?}");
        match res {
            WaitStatus::Signaled(_, signal, _) => match signal {
                nix::sys::signal::Signal::SIGALRM | nix::sys::signal::Signal::SIGUSR2 => {
                    Ok(ExitKind::Timeout)
                }
                _ => Ok(ExitKind::Crash),
            },
            WaitStatus::Exited(_, code) => {
                if code > 128 && code < 160 {
                    // Signal exit codes
                    let signal = code - 128;
                    if signal == Signal::SigAlarm as libc::c_int
                        || signal == Signal::SigUser2 as libc::c_int
                    {
                        Ok(ExitKind::Timeout)
                    } else {
                        Ok(ExitKind::Crash)
                    }
                } else {
                    Ok(ExitKind::Ok)
                }
            }
            _ => Ok(ExitKind::Ok),
        }
    }
}

impl<HT, OT, S, SP, EM, Z> GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z>
where
    HT: ExecutorHooksTuple<S>,
    S: State,
    OT: ObserversTuple<S::Input, S>,
{
    #[inline]
    /// This function marks the boundary between the fuzzer and the target.
    pub fn enter_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut <Self as UsesState>::State,
        _event_mgr: &mut EM,
        input: &<Self as UsesInput>::Input,
    ) {
        unsafe {
            let data = &raw mut FORK_EXECUTOR_GLOBAL_DATA;
            write_volatile(
                &raw mut (*data).executor_ptr,
                ptr::from_ref(self) as *const c_void,
            );
            write_volatile(
                &raw mut (*data).current_input_ptr,
                ptr::from_ref(input) as *const c_void,
            );
            write_volatile(
                &raw mut ((*data).state_ptr),
                ptr::from_mut(state) as *mut c_void,
            );
            compiler_fence(Ordering::SeqCst);
        }
    }

    #[inline]
    /// This function marks the boundary between the fuzzer and the target.
    pub fn leave_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut <Self as UsesState>::State,
        _event_mgr: &mut EM,
        _input: &<Self as UsesInput>::Input,
    ) {
        // do nothing
    }

    /// Creates a new [`GenericInProcessForkExecutorInner`] with custom hooks
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn with_hooks(
        userhooks: HT,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error> {
        let default_hooks = InChildProcessHooks::new::<Self>()?;
        let mut hooks = tuple_list!(default_hooks).merge(userhooks);
        hooks.init_all::<Self>(state);
        let itimerspec = parse_itimerspec(timeout);
        Ok(Self {
            shmem_provider,
            observers,
            hooks,
            itimerspec,
            phantom: PhantomData,
        })
    }

    /// Creates a new [`GenericInProcessForkExecutorInner`], non linux
    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::too_many_arguments)]
    pub fn with_hooks(
        userhooks: HT,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error> {
        let default_hooks = InChildProcessHooks::new::<Self>()?;
        let mut hooks = tuple_list!(default_hooks).merge(userhooks);
        hooks.init_all::<Self>(state);

        let itimerval = parse_itimerval(timeout);

        Ok(Self {
            shmem_provider,
            observers,
            hooks,
            itimerval,
            phantom: PhantomData,
        })
    }
}

impl<HT, OT, S, SP, EM, Z> HasObservers for GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z>
where
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    type Observers = OT;

    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}
