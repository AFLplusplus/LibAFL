//! The `StatefulGenericInProcessForkExecutor` to do forking before executing the harness in-processly. Harness can access internal state.
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    time::Duration,
};

use libafl_bolts::{shmem::ShMemProvider, tuples::tuple_list};
use nix::unistd::{fork, ForkResult};

use super::super::hooks::ExecutorHooksTuple;
use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        inprocess_fork::GenericInProcessForkExecutorInner, Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::{HasExecutions, HasSolutions, State, UsesState},
    Error,
};

/// The `StatefulInProcessForkExecutor` with no user hooks
pub type StatefulInProcessForkExecutor<'a, H, OT, S, SP, ES, EM, Z> =
    StatefulGenericInProcessForkExecutor<'a, H, (), OT, S, SP, ES, EM, Z>;

impl<'a, H, OT, S, SP, ES, EM, Z, OF> StatefulInProcessForkExecutor<'a, H, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&S::Input, &mut ES) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    OF: Feedback<S>,
    S: State + HasSolutions,
    Z: HasObjective<Objective = OF, State = S>,
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
    H: FnMut(&S::Input, &mut ES) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    harness_fn: &'a mut H,
    exposed_executor_state: ES,
    inner: GenericInProcessForkExecutorInner<HT, OT, S, SP, EM, Z>,
    phantom: PhantomData<ES>,
}

impl<'a, H, HT, OT, S, SP, ES, EM, Z> Debug
    for StatefulGenericInProcessForkExecutor<'a, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&S::Input, &mut ES) -> ExitKind + ?Sized,
    OT: ObserversTuple<S> + Debug,
    S: UsesInput,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S> + Debug,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
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

impl<'a, H, HT, OT, S, SP, ES, EM, Z> UsesState
    for StatefulGenericInProcessForkExecutor<'a, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&S::Input, &mut ES) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S>,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    type State = S;
}

impl<'a, EM, H, HT, OT, S, SP, Z, ES, OF> Executor<EM, Z>
    for StatefulGenericInProcessForkExecutor<'a, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&S::Input, &mut ES) -> ExitKind + ?Sized,
    OT: ObserversTuple<S> + Debug,
    S: State + HasExecutions,
    SP: ShMemProvider,
    HT: ExecutorHooksTuple<S>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    Z: HasObjective<Objective = OF, State = S>,
    OF: Feedback<S>,
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
                    (self.harness_fn)(input, &mut self.exposed_executor_state);
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

impl<'a, H, HT, OT, S, SP, ES, EM, Z, OF>
    StatefulGenericInProcessForkExecutor<'a, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&S::Input, &mut ES) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    OF: Feedback<S>,
    S: State + HasSolutions,
    Z: HasObjective<Objective = OF, State = S>,
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

impl<'a, H, HT, OT, S, SP, ES, EM, Z> UsesObservers
    for StatefulGenericInProcessForkExecutor<'a, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&S::Input, &mut ES) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    type Observers = OT;
}

impl<'a, H, HT, OT, S, SP, ES, EM, Z> HasObservers
    for StatefulGenericInProcessForkExecutor<'a, H, HT, OT, S, SP, ES, EM, Z>
where
    H: FnMut(&S::Input, &mut ES) -> ExitKind + ?Sized,
    HT: ExecutorHooksTuple<S>,
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.inner.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.inner.observers_mut()
    }
}
