use alloc::boxed::Box;
use core::{
    borrow::BorrowMut,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    time::Duration,
};

use libafl_bolts::tuples::tuple_list;
#[cfg(windows)]
use windows::Win32::System::Threading::SetThreadStackGuarantee;

use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::{inprocess::InProcessHooks, ExecutorHooksTuple},
        inprocess::{GenericInProcessExecutorInner, HasInProcessHooks},
        Executor, ExitKind, HasExecutorState, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::{HasCorpus, HasExecutions, HasSolutions, State, UsesState},
    Error,
};

/// The process executor simply calls a target function, as mutable reference to a closure
/// The internal state of the executor is made available to the harness.
pub type InProcessExecutorWithState<'a, H, OT, S, ES> =
    GenericInProcessExecutorWithState<H, &'a mut H, (), OT, S, ES>;

/// The process executor simply calls a target function, as boxed `FnMut` trait object
/// The internal state of the executor is made available to the harness.
pub type OwnedInProcessExecutor<OT, S, ES> = GenericInProcessExecutorWithState<
    dyn FnMut(&<S as UsesInput>::Input, &mut <ES as HasExecutorState>::ExecutorState) -> ExitKind,
    Box<
        dyn FnMut(
            &<S as UsesInput>::Input,
            &mut <ES as HasExecutorState>::ExecutorState,
        ) -> ExitKind,
    >,
    (),
    OT,
    S,
    ES,
>;

/// The inmem executor simply calls a target function, then returns afterwards.
/// The harness can access the internal state of the executor.
#[allow(dead_code)]
pub struct GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    H: FnMut(&S::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
    ES: HasExecutorState,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: HB,
    /// Inner state of the executor
    inner: GenericInProcessExecutorInner<HT, OT, S>,
    phantom: PhantomData<(ES, *const H)>,
}

impl<H, HB, HT, OT, S, ES> Debug for GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    H: FnMut(&S::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S> + Debug,
    S: State,
    ES: HasExecutorState,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessExecutorWithState")
            .field("harness_fn", &"<fn>")
            .field("executor_state", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<H, HB, HT, OT, S, ES> UsesState for GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    H: FnMut(&S::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
    ES: HasExecutorState,
{
    type State = S;
}

impl<H, HB, HT, OT, S, ES> UsesObservers for GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    H: FnMut(&S::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
    ES: HasExecutorState,
{
    type Observers = OT;
}

impl<H, HB, HT, OT, S, ES> HasExecutorState
    for GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    H: FnMut(&S::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
    ES: HasExecutorState,
{
    type ExecutorState = GenericInProcessExecutorInner<HT, OT, S>;
}

impl<EM, H, HB, HT, OT, S, Z, ES> Executor<EM, Z, ES>
    for GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    EM: UsesState<State = S>,
    H: FnMut(&S::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State + HasExecutions,
    Z: UsesState<State = S>,
    ES: HasExecutorState,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
        executor_state: &mut ES::ExecutorState,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;
        self.inner.enter_target(fuzzer, state, mgr, input);
        self.inner.hooks.pre_exec_all(fuzzer, state, mgr, input);

        let ret = (self.harness_fn.borrow_mut())(input, executor_state);

        self.inner.hooks.post_exec_all(fuzzer, state, mgr, input);
        self.inner.leave_target(fuzzer, state, mgr, input);
        Ok(ret)
    }
}

impl<H, HB, HT, OT, S, ES> HasObservers for GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    H: FnMut(&S::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
    ES: HasExecutorState,
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

impl<'a, H, OT, S, ES> InProcessExecutorWithState<'a, H, OT, S, ES>
where
    H: FnMut(&<S as UsesInput>::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: HasExecutions + HasSolutions + HasCorpus + State,
    ES: HasExecutorState,
{
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, ES, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        Self::with_timeout_generic(
            tuple_list!(),
            harness_fn,
            observers,
            fuzzer,
            state,
            event_mgr,
            Duration::from_millis(5000),
        )
    }

    /// Create a new in mem executor with the default timeout and use batch mode(5 sec)
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn batched_timeouts<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, ES, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let inner = GenericInProcessExecutorInner::batched_timeouts::<Self, ES, EM, OF, Z>(
            observers, fuzzer, state, event_mgr, exec_tmout,
        )?;

        Ok(Self {
            harness_fn,
            inner,
            phantom: PhantomData,
        })
    }

    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `user_hooks` - the hooks run before and after the harness's execution
    /// * `harness_fn` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn with_timeout<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, ES, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let inner = GenericInProcessExecutorInner::with_timeout::<Self, ES, EM, OF, Z>(
            observers, fuzzer, state, event_mgr, timeout,
        )?;

        Ok(Self {
            harness_fn,
            inner,
            phantom: PhantomData,
        })
    }
}

impl<H, HB, HT, OT, S, ES> GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    H: FnMut(&S::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State + HasExecutions + HasSolutions + HasCorpus,
    ES: HasExecutorState,
{
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        Self::with_timeout_generic(
            user_hooks,
            harness_fn,
            observers,
            fuzzer,
            state,
            event_mgr,
            Duration::from_millis(5000),
        )
    }

    /// Create a new in mem executor with the default timeout and use batch mode(5 sec)
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn batched_timeout_generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let inner = GenericInProcessExecutorInner::batched_timeout_generic::<Self, ES, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, exec_tmout,
        )?;

        Ok(Self {
            harness_fn,
            inner,
            phantom: PhantomData,
        })
    }

    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `user_hooks` - the hooks run before and after the harness's execution
    /// * `harness_fn` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn with_timeout_generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let inner = GenericInProcessExecutorInner::with_timeout_generic::<Self, ES, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, timeout,
        )?;

        Ok(Self {
            harness_fn,
            inner,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness_fn.borrow()
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn.borrow_mut()
    }

    /// The inprocess handlers
    #[inline]
    pub fn hooks(&self) -> &(InProcessHooks, HT) {
        self.inner.hooks()
    }

    /// The inprocess handlers (mutable)
    #[inline]
    pub fn hooks_mut(&mut self) -> &mut (InProcessHooks, HT) {
        self.inner.hooks_mut()
    }
}

impl<H, HB, HT, OT, S, ES> HasInProcessHooks
    for GenericInProcessExecutorWithState<H, HB, HT, OT, S, ES>
where
    H: FnMut(&<S as UsesInput>::Input, &mut ES::ExecutorState) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State + HasExecutions + HasSolutions + HasCorpus,
    ES: HasExecutorState,
{
    /// the timeout handler
    #[inline]
    fn inprocess_hooks(&self) -> &InProcessHooks {
        self.inner.inprocess_hooks()
    }

    /// the timeout handler
    #[inline]
    fn inprocess_hooks_mut(&mut self) -> &mut InProcessHooks {
        self.inner.inprocess_hooks_mut()
    }
}
