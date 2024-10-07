//! A version of `InProcessForkExecutor` with a state accessible from the harness.
//!
//! The `StatefulGenericInProcessForkExecutor` to do forking before executing the harness in-process.
//! The harness can access internal state.
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    time::Duration,
};

use libafl_bolts::{
    shmem::ShMemProvider,
    tuples::{tuple_list, RefIndexable},
};
use nix::unistd::{fork, ForkResult};

use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::ExecutorHooksTuple, inprocess_fork::GenericInProcessForkExecutorInner, Executor,
        ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::ObserversTuple,
    state::{HasExecutions, State, UsesState},
    Error,
};

/// The `StatefulInProcessForkExecutor` with no user hooks
pub type StatefulInProcessForkExecutor<'a, H, OT, S, SP, ES, EM, Z> =
    StatefulGenericInProcessForkExecutor<'a, H, (), OT, S, SP, ES, EM, Z>;

impl<'a, H, OT, S, SP, ES, EM, Z> StatefulInProcessForkExecutor<'a, H, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&mut ES, &S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    #[allow(clippy::too_many_arguments)]
    /// The constructor for `InProcessForkExecutor`
    pub fn new(
        harness_fn: &'a mut H,
        exposed_executor_state: ES,
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
            exposed_executor_state,
            observers,
            fuzzer,
            state,
            event_mgr,
            timeout,
            shmem_provider,
        )
    }
}

/// [`StatefulGenericInProcessForkExecutor`] is an executor that forks the current process before each execution. Harness can access some internal state.
pub struct StatefulGenericInProcessForkExecutor<'a, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&mut ES, &S::Input) -> ExitKind + ?Sized,
    S: UsesInput,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: &'a mut H,
    /// The state used as argument of the harness
    pub exposed_executor_state: ES,
    /// Inner state of the executor
    pub inner: GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z>,
    phantom: PhantomData<ES>,
}

impl<H, HT, OT, S, SP, ES, EM, Z> Debug
    for StatefulGenericInProcessForkExecutor<'_, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&mut ES, &S::Input) -> ExitKind + ?Sized,
    HT: Debug,
    OT: Debug,
    S: UsesInput,
    SP: Debug,
{
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessForkExecutor")
            .field("GenericInProcessForkExecutionInner", &self.inner)
            .finish()
    }

    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[cfg(not(target_os = "linux"))]
        return f
            .debug_struct("GenericInProcessForkExecutor")
            .field("GenericInProcessForkExecutionInner", &self.inner)
            .finish();
    }
}

impl<H, HT, OT, S, SP, ES, EM, Z> UsesState
    for StatefulGenericInProcessForkExecutor<'_, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&mut ES, &S::Input) -> ExitKind + ?Sized,
    S: State,
{
    type State = S;
}

impl<EM, H, HT, OT, S, SP, Z, ES, OF> Executor<EM, Z>
    for StatefulGenericInProcessForkExecutor<'_, H, HT, OT, S, SP, ES, EM, Z>
where
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    H: FnMut(&mut ES, &S::Input) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple<S>,
    OF: Feedback<EM, S::Input, OT, S>,
    OT: ObserversTuple<S::Input, S> + Debug,
    S: State + HasExecutions,
    SP: ShMemProvider,
    Z: HasObjective<Objective = OF, State = S>,
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
                    (self.harness_fn)(&mut self.exposed_executor_state, input);
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

impl<'a, H, HT, OT, S, SP, ES, EM, Z>
    StatefulGenericInProcessForkExecutor<'a, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&mut ES, &S::Input) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    /// Creates a new [`StatefulGenericInProcessForkExecutor`] with custom hooks
    #[allow(clippy::too_many_arguments)]
    pub fn with_hooks(
        userhooks: HT,
        harness_fn: &'a mut H,
        exposed_executor_state: ES,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error> {
        Ok(Self {
            harness_fn,
            exposed_executor_state,
            inner: GenericInProcessForkExecutorInner::with_hooks(
                userhooks,
                observers,
                fuzzer,
                state,
                event_mgr,
                timeout,
                shmem_provider,
            )?,
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

impl<H, HT, OT, S, SP, ES, EM, Z> HasObservers
    for StatefulGenericInProcessForkExecutor<'_, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&mut ES, &S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: State,
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
