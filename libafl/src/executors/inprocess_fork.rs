use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr::{addr_of_mut, null_mut},
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
        hooks::inprocess_fork::{InChildProcessHooks, InProcessForkExecutorGlobalData},
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
    data: &mut InProcessForkExecutorGlobalData,
);

#[repr(C)]
#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
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
#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
#[derive(Debug)]
struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
extern "C" {
    fn setitimer(
        which: libc::c_int,
        new_value: *mut Itimerval,
        old_value: *mut Itimerval,
    ) -> libc::c_int;
}

#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
const ITIMER_REAL: libc::c_int = 0;

/// [`InProcessForkExecutor`] is an executor that forks the current process before each execution.
pub struct InProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple,
{
    harness_fn: &'a mut H,
    shmem_provider: SP,
    observers: OT,
    hooks: (InChildProcessHooks, HT),
    #[cfg(target_os = "linux")]
    itimerspec: libc::itimerspec,
    #[cfg(all(unix, not(target_os = "linux")))]
    itimerval: Itimerval,
    phantom: PhantomData<S>,
}

impl<'a, H, HT, OT, S, SP> Debug for InProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S> + Debug,
    S: UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple,
{
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessForkExecutor")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .field("itimerspec", &self.itimerspec)
            .finish()
    }

    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[cfg(not(target_os = "linux"))]
        return f
            .debug_struct("InProcessForkExecutor")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .field("itimerval", &self.itimerval)
            .finish();
    }
}

impl<'a, H, HT, OT, S, SP> UsesState for InProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple,
{
    type State = S;
}

impl<'a, EM, H, HT, OT, S, SP, Z> Executor<EM, Z> for InProcessForkExecutor<'a, H, HT, OT, S, SP>
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
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        unsafe {
            self.shmem_provider.pre_fork()?;
            match fork() {
                Ok(ForkResult::Child) => {
                    // Child
                    self.shmem_provider.post_fork(true)?;

                    self.hooks.pre_exec_all(self, state, input);

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

impl<'a, H, HT, OT, S, SP> InProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple,
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
{
    /// Creates a new [`InProcessForkExecutor`] with custom hooks
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
        userhooks: HT,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let default_hooks = InChildProcessHooks::new()?;
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

    /// Creates a new [`InProcessForkExecutor`], non linux
    #[cfg(not(target_os = "linux"))]
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
        hooks: HT,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let hooks = InChildProcessHooks::new::<Self>()?;
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

impl<'a, H, HT, OT, S, SP> UsesObservers for InProcessForkExecutor<'a, H, HT, OT, S, SP>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    type Observers = OT;
}

impl<'a, H, HT, OT, S, SP> HasObservers for InProcessForkExecutor<'a, H, HT, OT, S, SP>
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
        panic::set_hook(Box::new(move |panic_info| {
            old_hook(panic_info);
            let data = unsafe { &mut FORK_EXECUTOR_GLOBAL_DATA };
            if data.is_valid() {
                let executor = data.executor_mut::<E>();
                let observers = executor.observers_mut();
                let state = data.state_mut::<E::State>();
                // Invalidate data to not execute again the observer hooks in the crash handler
                let input = data.take_current_input::<<E::State as UsesInput>::Input>();
                observers
                    .post_exec_child_all(state, input, &ExitKind::Crash)
                    .expect("Failed to run post_exec on observers");

                // std::process::abort();
                unsafe { libc::_exit(128 + 6) }; // ABORT exit code
            }
        }));
    }

    /// invokes the `post_exec` hook on all observer in case the child process crashes
    ///
    /// # Safety
    /// The function should only be called from a child crash handler.
    /// It will dereference the `data` pointer and assume it's valid.
    #[cfg(unix)]
    pub(crate) unsafe fn child_crash_handler<E>(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: &Option<&mut ucontext_t>,
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
    pub(crate) unsafe fn child_timeout_handler<E>(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: &Option<&mut ucontext_t>,
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
        use libc::{itimerspec, timespec};

        use crate::{
            events::SimpleEventManager,
            executors::{
                hooks::inprocess_fork::InChildProcessHooks, Executor, InProcessForkExecutor,
            },
            fuzzer::test::NopFuzzer,
            state::test::NopState,
        };

        let provider = StdShMemProvider::new().unwrap();

        let timespec = timespec {
            tv_sec: 5,
            tv_nsec: 0,
        };
        let itimerspec = itimerspec {
            it_interval: timespec,
            it_value: timespec,
        };

        let mut harness = |_buf: &NopInput| ExitKind::Ok;
        let mut in_process_fork_executor = InProcessForkExecutor::<_, (), (), _, _> {
            harness_fn: &mut harness,
            shmem_provider: provider,
            observers: tuple_list!(),
            hooks: tuple_list!(InChildProcessHooks::new().unwrap()),
            itimerspec,
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
