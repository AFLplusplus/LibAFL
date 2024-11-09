//! The `GenericInProcessForkExecutor` to do forking before executing the harness in-processly
use core::{
    fmt::{self, Debug, Formatter},
    time::Duration,
};

use libafl_bolts::{
    os::unix_signals::{ucontext_t, Signal},
    shmem::ShMemProvider,
    tuples::{tuple_list, RefIndexable},
};
use libc::siginfo_t;
use nix::unistd::{fork, ForkResult};

use super::hooks::ExecutorHooksTuple;
use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::inprocess_fork::InProcessForkExecutorGlobalData,
        inprocess_fork::inner::GenericInProcessForkExecutorInner, Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::ObserversTuple,
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

/// The inner structure of `InProcessForkExecutor`.
pub mod inner;
pub mod stateful;

/// The `InProcessForkExecutor` with no user hooks.
///
/// On Linux, when fuzzing a Rust target, set `panic = "abort"` in your `Cargo.toml` (see [Cargo documentation](https://doc.rust-lang.org/cargo/reference/profiles.html#panic)).
/// Else panics can not be caught by `LibAFL`.
pub type InProcessForkExecutor<'a, H, OT, S, SP, EM, Z> =
    GenericInProcessForkExecutor<'a, H, (), OT, S, SP, EM, Z>;

impl<'a, H, OT, S, SP, EM, Z, OF> InProcessForkExecutor<'a, H, OT, S, SP, EM, Z>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    S: State,
    OT: ObserversTuple<S::Input, S>,
    SP: ShMemProvider,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    OF: Feedback<EM, S::Input, OT, S>,
    S: HasSolutions,
    Z: HasObjective<Objective = OF, State = S>,
{
    #[allow(clippy::too_many_arguments)]
    /// The constructor for `InProcessForkExecutor`
    pub fn new(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error> {
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
///
/// On Linux, when fuzzing a Rust target, set `panic = "abort"` in your `Cargo.toml` (see [Cargo documentation](https://doc.rust-lang.org/cargo/reference/profiles.html#panic)).
/// Else panics can not be caught by `LibAFL`.
pub struct GenericInProcessForkExecutor<'a, H, HT, OT, S, SP, EM, Z>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    harness_fn: &'a mut H,
    inner: GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z>,
}

impl<H, HT, OT, S, SP, EM, Z> Debug for GenericInProcessForkExecutor<'_, H, HT, OT, S, SP, EM, Z>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S> + Debug,
    S: UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S> + Debug,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessForkExecutor")
            .field("GenericInProcessForkExecutorInner", &self.inner)
            .finish()
    }

    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[cfg(not(target_os = "linux"))]
        return f
            .debug_struct("GenericInProcessForkExecutor")
            .field("GenericInProcessForkExecutorInner", &self.inner)
            .finish();
    }
}

impl<H, HT, OT, S, SP, EM, Z> UsesState
    for GenericInProcessForkExecutor<'_, H, HT, OT, S, SP, EM, Z>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: State,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    type State = S;
}

impl<EM, H, HT, OT, S, SP, Z> Executor<EM, Z>
    for GenericInProcessForkExecutor<'_, H, HT, OT, S, SP, EM, Z>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S> + Debug,
    S: State + HasExecutions,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
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
            self.inner.shmem_provider.pre_fork()?;
            match fork() {
                Ok(ForkResult::Child) => {
                    // Child
                    self.inner.pre_run_target_child(fuzzer, state, mgr, input)?;
                    (self.harness_fn)(input);
                    self.inner.post_run_target_child(fuzzer, state, mgr, input);
                    Ok(ExitKind::Ok)
                }
                Ok(ForkResult::Parent { child }) => {
                    // Parent
                    self.inner.parent(child)
                }
                Err(e) => Err(Error::from(e)),
            }
        }
    }
}

impl<'a, H, HT, OT, S, SP, EM, Z, OF> GenericInProcessForkExecutor<'a, H, HT, OT, S, SP, EM, Z>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    SP: ShMemProvider,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    OF: Feedback<EM, S::Input, OT, S>,
    S: State + HasSolutions,
    Z: HasObjective<Objective = OF, State = S>,
{
    /// Creates a new [`GenericInProcessForkExecutor`] with custom hooks
    #[allow(clippy::too_many_arguments)]
    pub fn with_hooks(
        userhooks: HT,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error>
where {
        Ok(Self {
            harness_fn,
            inner: GenericInProcessForkExecutorInner::with_hooks(
                userhooks,
                observers,
                fuzzer,
                state,
                event_mgr,
                timeout,
                shmem_provider,
            )?,
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

impl<H, HT, OT, S, SP, EM, Z> HasObservers
    for GenericInProcessForkExecutor<'_, H, HT, OT, S, SP, EM, Z>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple<S>,
    S: State,
    OT: ObserversTuple<S::Input, S>,
    SP: ShMemProvider,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    type Observers = OT;
    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        self.inner.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        self.inner.observers_mut()
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
        state::UsesState,
    };

    /// invokes the `post_exec_child` hook on all observer in case the child process panics
    pub fn setup_child_panic_hook<E>()
    where
        E: HasObservers + UsesState,
        E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
    {
        let old_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| unsafe {
            old_hook(panic_info);
            let data = &raw mut FORK_EXECUTOR_GLOBAL_DATA;
            if !data.is_null() && (*data).is_valid() {
                let executor = (*data).executor_mut::<E>();
                let mut observers = executor.observers_mut();
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
        E: HasObservers + UsesState,
        E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
    {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let mut observers = executor.observers_mut();
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
        E: HasObservers + UsesState,
        E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
    {
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            let mut observers = executor.observers_mut();
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
#[cfg(all(feature = "std", feature = "fork", unix))]
mod tests {
    use libafl_bolts::tuples::tuple_list;
    use serial_test::serial;

    use crate::{
        executors::{inprocess_fork::GenericInProcessForkExecutorInner, Executor, ExitKind},
        inputs::NopInput,
    };

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
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
                inprocess_fork::GenericInProcessForkExecutor,
            },
            fuzzer::NopFuzzer,
            state::NopState,
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
        let mut in_process_fork_executor = GenericInProcessForkExecutor {
            harness_fn: &mut harness,
            inner: GenericInProcessForkExecutorInner {
                hooks: tuple_list!(default),
                shmem_provider: provider,
                observers: tuple_list!(),
                itimerspec,
                phantom: PhantomData,
            },
        };
        #[cfg(not(target_os = "linux"))]
        let mut in_process_fork_executor = GenericInProcessForkExecutor {
            harness_fn: &mut harness,
            inner: GenericInProcessForkExecutorInner {
                hooks: tuple_list!(default),
                shmem_provider: provider,
                observers: tuple_list!(),
                itimerval: itimerspec,
                phantom: PhantomData,
            },
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
