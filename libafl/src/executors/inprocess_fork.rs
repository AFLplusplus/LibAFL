//! The `GenericInProcessForkExecutor` to do forking before executing the harness in-processly
use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr::{addr_of_mut, null_mut, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};

use libafl_bolts::{
    os::unix_signals::{ucontext_t, Signal},
    shmem::ShMemProvider,
    tuples::{tuple_list, Merge},
};
use libc::siginfo_t;
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::{fork, ForkResult},
};

use super::hooks::ExecutorHooksTuple;
use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::inprocess_fork::{
            InChildProcessHooks, InProcessForkExecutorGlobalData, FORK_EXECUTOR_GLOBAL_DATA,
        },
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::{HasExecutions, HasSolutions, State, UsesState},
    Error,
};
/// The signature of the crash handler function
pub(crate) type ForkHandlerFuncPtr = unsafe fn(
    Signal,
    &mut siginfo_t,
    Option<&mut ucontext_t>,
    data: *mut InProcessForkExecutorGlobalData,
);

#[cfg(all(unix, not(target_os = "linux")))]
use crate::executors::hooks::timer::{setitimer, Itimerval, Timeval, ITIMER_REAL};

/// The `InProcessForkExecutor` with no user hooks
pub type InProcessForkExecutor<'a, H, OT, S, SP> =
    GenericInProcessForkExecutor<'a, H, (), OT, S, SP>;

impl<'a, H, OT, S, SP> InProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
{
    #[allow(clippy::too_many_arguments)]
    /// The constructor for `InProcessForkExecutor`
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        Self::with_hooks(
            tuple_list!(),
            harness_fn,
            observers,
            fuzzer,
            state,
            event_mgr,
            timeout,
            shmem_provider,
        )
    }
}

/// [`GenericInProcessForkExecutor`] is an executor that forks the current process before each execution.
pub struct GenericInProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple,
{
    hooks: (InChildProcessHooks, HT),
    harness_fn: &'a mut H,
    shmem_provider: SP,
    observers: OT,
    #[cfg(target_os = "linux")]
    itimerspec: libc::itimerspec,
    #[cfg(all(unix, not(target_os = "linux")))]
    itimerval: Itimerval,
    phantom: PhantomData<S>,
}

impl<'a, H, HT, OT, S, SP> Debug for GenericInProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S> + Debug,
    S: UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple,
{
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessForkExecutor")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .field("itimerspec", &self.itimerspec)
            .finish()
    }

    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[cfg(not(target_os = "linux"))]
        return f
            .debug_struct("GenericInProcessForkExecutor")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .field("itimerval", &self.itimerval)
            .finish();
    }
}

impl<'a, H, HT, OT, S, SP> UsesState for GenericInProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple,
{
    type State = S;
}

impl<'a, EM, H, HT, OT, S, SP, Z> Executor<EM, Z>
    for GenericInProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    EM: UsesState<State = S>,
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: State + HasExecutions,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple,
    Z: UsesState<State = S>,
{
    #[allow(unreachable_code)]
    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        unsafe {
            self.shmem_provider.pre_fork()?;
            match fork() {
                Ok(ForkResult::Child) => {
                    // Child
                    self.shmem_provider.post_fork(true)?;

                    self.enter_target(fuzzer, state, mgr, input);
                    self.hooks.pre_exec_all(fuzzer, state, mgr, input);

                    self.observers
                        .pre_exec_child_all(state, input)
                        .expect("Failed to run post_exec on observers");

                    #[cfg(target_os = "linux")]
                    {
                        let mut timerid: libc::timer_t = null_mut();
                        // creates a new per-process interval timer
                        // we can't do this from the parent, timerid is unique to each process.
                        libc::timer_create(
                            libc::CLOCK_MONOTONIC,
                            null_mut(),
                            addr_of_mut!(timerid),
                        );

                        // log::info!("Set timer! {:#?} {timerid:#?}", self.itimerspec);
                        let _: i32 = libc::timer_settime(
                            timerid,
                            0,
                            addr_of_mut!(self.itimerspec),
                            null_mut(),
                        );
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        setitimer(ITIMER_REAL, &mut self.itimerval, null_mut());
                    }
                    // log::trace!("{v:#?} {}", nix::errno::errno());
                    (self.harness_fn)(input);

                    self.observers
                        .post_exec_child_all(state, input, &ExitKind::Ok)
                        .expect("Failed to run post_exec on observers");

                    self.hooks.post_exec_all(fuzzer, state, mgr, input);
                    self.leave_target(fuzzer, state, mgr, input);

                    libc::_exit(0);

                    Ok(ExitKind::Ok)
                }
                Ok(ForkResult::Parent { child }) => {
                    // Parent
                    // log::trace!("from parent {} child is {}", std::process::id(), child);
                    self.shmem_provider.post_fork(false)?;

                    let res = waitpid(child, None)?;
                    log::trace!("{res:#?}");
                    match res {
                        WaitStatus::Signaled(_, signal, _) => match signal {
                            nix::sys::signal::Signal::SIGALRM
                            | nix::sys::signal::Signal::SIGUSR2 => Ok(ExitKind::Timeout),
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
                Err(e) => Err(Error::from(e)),
            }
        }
    }
}

impl<'a, H, HT, OT, S, SP> GenericInProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple,
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
{
    #[inline]
    /// This function marks the boundary between the fuzzer and the target.
    pub fn enter_target<EM, Z>(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut <Self as UsesState>::State,
        _event_mgr: &mut EM,
        input: &<Self as UsesInput>::Input,
    ) {
        unsafe {
            let data = addr_of_mut!(FORK_EXECUTOR_GLOBAL_DATA);
            write_volatile(
                addr_of_mut!((*data).executor_ptr),
                core::ptr::from_ref(self) as *const c_void,
            );
            write_volatile(
                addr_of_mut!((*data).current_input_ptr),
                core::ptr::from_ref(input) as *const c_void,
            );
            write_volatile(
                addr_of_mut!((*data).state_ptr),
                core::ptr::from_mut(state) as *mut c_void,
            );
            compiler_fence(Ordering::SeqCst);
        }
    }

    #[inline]
    /// This function marks the boundary between the fuzzer and the target.
    pub fn leave_target<EM, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut <Self as UsesState>::State,
        _event_mgr: &mut EM,
        _input: &<Self as UsesInput>::Input,
    ) {
        // do nothing
    }

    /// Creates a new [`GenericInProcessForkExecutor`] with custom hooks
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn with_hooks<EM, OF, Z>(
        userhooks: HT,
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let default_hooks = InChildProcessHooks::new::<Self>()?;
        let mut hooks = tuple_list!(default_hooks).merge(userhooks);
        hooks.init_all::<Self, S>(state);

        let milli_sec = timeout.as_millis();
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

        Ok(Self {
            harness_fn,
            shmem_provider,
            observers,
            hooks,
            itimerspec,
            phantom: PhantomData,
        })
    }

    /// Creates a new [`GenericInProcessForkExecutor`], non linux
    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::too_many_arguments)]
    pub fn with_hooks<EM, OF, Z>(
        userhooks: HT,
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let default_hooks = InChildProcessHooks::new::<Self>()?;
        let mut hooks = tuple_list!(default_hooks).merge(userhooks);
        hooks.init_all::<Self, S>(state);

        let milli_sec = timeout.as_millis();
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
            harness_fn,
            shmem_provider,
            observers,
            hooks,
            itimerval,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness_fn
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn
    }
}

impl<'a, H, HT, OT, S, SP> UsesObservers for GenericInProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    type Observers = OT;
}

impl<'a, H, HT, OT, S, SP> HasObservers for GenericInProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple,
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
{
    #[inline]
    fn observers(&self) -> &OT {
        &self.observers
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
/// signal hooks and `panic_hooks` for the child process

pub mod child_signal_handlers {
    use alloc::boxed::Box;
    use core::ptr::addr_of_mut;
    use std::panic;

    use libafl_bolts::os::unix_signals::{ucontext_t, Signal};
    use libc::siginfo_t;

    use crate::{
        executors::{
            hooks::inprocess_fork::{InProcessForkExecutorGlobalData, FORK_EXECUTOR_GLOBAL_DATA},
            ExitKind, HasObservers,
        },
        inputs::UsesInput,
        observers::ObserversTuple,
    };

    /// invokes the `post_exec_child` hook on all observer in case the child process panics
    pub fn setup_child_panic_hook<E>()
    where
        E: HasObservers,
    {
        let old_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| unsafe {
            old_hook(panic_info);
            let data = addr_of_mut!(FORK_EXECUTOR_GLOBAL_DATA);
            if !data.is_null() && (*data).is_valid() {
                let executor = (*data).executor_mut::<E>();
                let observers = executor.observers_mut();
                let state = (*data).state_mut::<E::State>();
                // Invalidate data to not execute again the observer hooks in the crash handler
                let input = (*data).take_current_input::<<E::State as UsesInput>::Input>();
                observers
                    .post_exec_child_all(state, input, &ExitKind::Crash)
                    .expect("Failed to run post_exec on observers");

                // std::process::abort();
                libc::_exit(128 + 6); // ABORT exit code
            }
        }));
    }

    /// invokes the `post_exec` hook on all observer in case the child process crashes
    ///
    /// # Safety
    /// The function should only be called from a child crash handler.
    /// It will dereference the `data` pointer and assume it's valid.
    #[cfg(unix)]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) unsafe fn child_crash_handler<E>(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
        data: &mut InProcessForkExecutorGlobalData,
    ) where
        E: HasObservers,
    {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let observers = executor.observers_mut();
            let state = data.state_mut::<E::State>();
            let input = data.take_current_input::<<E::State as UsesInput>::Input>();
            observers
                .post_exec_child_all(state, input, &ExitKind::Crash)
                .expect("Failed to run post_exec on observers");
        }

        libc::_exit(128 + (_signal as i32));
    }

    #[cfg(unix)]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) unsafe fn child_timeout_handler<E>(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
        data: &mut InProcessForkExecutorGlobalData,
    ) where
        E: HasObservers,
    {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let observers = executor.observers_mut();
            let state = data.state_mut::<E::State>();
            let input = data.take_current_input::<<E::State as UsesInput>::Input>();
            observers
                .post_exec_child_all(state, input, &ExitKind::Timeout)
                .expect("Failed to run post_exec on observers");
        }
        libc::_exit(128 + (_signal as i32));
    }
}

#[cfg(test)]
mod tests {
    use libafl_bolts::tuples::tuple_list;

    use crate::{executors::ExitKind, inputs::NopInput};

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg(all(feature = "std", feature = "fork", unix))]
    fn test_inprocessfork_exec() {
        use core::marker::PhantomData;

        use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};
        #[cfg(target_os = "linux")]
        use libc::{itimerspec, timespec};

        #[cfg(not(target_os = "linux"))]
        use crate::executors::hooks::timer::{Itimerval, Timeval};
        use crate::{
            events::SimpleEventManager,
            executors::{
                hooks::inprocess_fork::InChildProcessHooks,
                inprocess_fork::GenericInProcessForkExecutor, Executor,
            },
            fuzzer::test::NopFuzzer,
            state::test::NopState,
        };

        let provider = StdShMemProvider::new().unwrap();

        #[cfg(target_os = "linux")]
        let timespec = timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        #[cfg(target_os = "linux")]
        let itimerspec = itimerspec {
            it_interval: timespec,
            it_value: timespec,
        };

        #[cfg(not(target_os = "linux"))]
        let timespec = Timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        #[cfg(not(target_os = "linux"))]
        let itimerspec = Itimerval {
            it_interval: timespec,
            it_value: timespec,
        };

        let mut harness = |_buf: &NopInput| ExitKind::Ok;
        let default = InChildProcessHooks::nop();
        #[cfg(target_os = "linux")]
        let mut in_process_fork_executor = GenericInProcessForkExecutor::<_, (), (), _, _> {
            hooks: tuple_list!(default),
            harness_fn: &mut harness,
            shmem_provider: provider,
            observers: tuple_list!(),
            itimerspec,
            phantom: PhantomData,
        };
        #[cfg(not(target_os = "linux"))]
        let mut in_process_fork_executor = GenericInProcessForkExecutor::<_, (), (), _, _> {
            harness_fn: &mut harness,
            shmem_provider: provider,
            observers: tuple_list!(),
            hooks: tuple_list!(default),
            itimerval: itimerspec,
            phantom: PhantomData,
        };
        let input = NopInput {};
        let mut fuzzer = NopFuzzer::new();
        let mut state = NopState::new();
        let mut mgr = SimpleEventManager::printing();
        in_process_fork_executor
            .run_target(&mut fuzzer, &mut state, &mut mgr, &input)
            .unwrap();
    }
}
