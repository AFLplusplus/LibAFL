use alloc::boxed::Box;
use core::{
    borrow::BorrowMut,
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr,
    time::Duration,
};

use libafl_bolts::tuples::{tuple_list, RefIndexable};

use crate::{
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::{inprocess::InProcessHooks, ExecutorHooksTuple},
        inprocess::{GenericInProcessExecutorInner, HasInProcessHooks},
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::ObserversTuple,
    state::{HasCorpus, HasExecutions, HasSolutions, State, UsesState},
    Error,
};

/// The process executor simply calls a target function, as mutable reference to a closure
/// The internal state of the executor is made available to the harness.
pub type StatefulInProcessExecutor<'a, H, OT, S, ES> =
    StatefulGenericInProcessExecutor<H, &'a mut H, (), OT, S, ES>;

/// The process executor simply calls a target function, as boxed `FnMut` trait object
/// The internal state of the executor is made available to the harness.
pub type OwnedInProcessExecutor<OT, S, ES> = StatefulGenericInProcessExecutor<
    dyn FnMut(&mut ES, &<S as UsesInput>::Input) -> ExitKind,
    Box<dyn FnMut(&mut ES, &<S as UsesInput>::Input) -> ExitKind>,
    (),
    OT,
    S,
    ES,
>;

/// The inmem executor simply calls a target function, then returns afterwards.
/// The harness can access the internal state of the executor.
#[allow(dead_code)]
pub struct StatefulGenericInProcessExecutor<H, HB, HT, OT, S, ES>
where
    H: FnMut(&mut ES, &mut S, &S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: HB,
    /// The state used as argument of the harness
    pub exposed_executor_state: ES,
    /// Inner state of the executor
    pub inner: GenericInProcessExecutorInner<HT, OT, S>,
    phantom: PhantomData<(ES, *const H)>,
}

impl<H, HB, HT, OT, S, ES> Debug for StatefulGenericInProcessExecutor<H, HB, HT, OT, S, ES>
where
    H: FnMut(&mut ES, &mut S, &S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S> + Debug,
    S: State,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulGenericInProcessExecutor")
            .field("harness_fn", &"<fn>")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<H, HB, HT, OT, S, ES> UsesState for StatefulGenericInProcessExecutor<H, HB, HT, OT, S, ES>
where
    H: FnMut(&mut ES, &mut S, &S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    type State = S;
}

impl<EM, H, HB, HT, OT, S, Z, ES> Executor<EM, Z>
    for StatefulGenericInProcessExecutor<H, HB, HT, OT, S, ES>
where
    EM: UsesState<State = S>,
    H: FnMut(&mut ES, &mut S, &S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasExecutions,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;
        unsafe {
            let executor_ptr = ptr::from_ref(self) as *const c_void;
            self.inner
                .enter_target(fuzzer, state, mgr, input, executor_ptr);
        }
        self.inner.hooks.pre_exec_all(state, input);

        let ret = self.harness_fn.borrow_mut()(&mut self.exposed_executor_state, state, input);

        self.inner.hooks.post_exec_all(state, input);
        self.inner.leave_target(fuzzer, state, mgr, input);
        Ok(ret)
    }
}

impl<H, HB, HT, OT, S, ES> HasObservers for StatefulGenericInProcessExecutor<H, HB, HT, OT, S, ES>
where
    H: FnMut(&mut ES, &mut S, &S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
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

impl<'a, H, OT, S, ES> StatefulInProcessExecutor<'a, H, OT, S, ES>
where
    H: FnMut(&mut ES, &mut S, &<S as UsesInput>::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: HasExecutions + HasSolutions + HasCorpus + State,
    <S as HasSolutions>::Solutions: Corpus<Input = S::Input>, //delete me
    <<S as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
{
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        exposed_executor_state: ES,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, S::Input, OT, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        Self::with_timeout_generic(
            tuple_list!(),
            harness_fn,
            exposed_executor_state,
            observers,
            fuzzer,
            state,
            event_mgr,
            Duration::from_millis(5000),
        )
    }

    /// Create a new in mem executor with the default timeout and use batch mode(5 sec)
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn batched_timeout<EM, OF, Z>(
        harness_fn: &'a mut H,
        exposed_executor_state: ES,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, S::Input, OT, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
        <S as HasSolutions>::Solutions: Corpus<Input = S::Input>, //delete me
        <<S as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
    {
        let inner = GenericInProcessExecutorInner::batched_timeout_generic::<Self, EM, OF, Z>(
            tuple_list!(),
            observers,
            fuzzer,
            state,
            event_mgr,
            exec_tmout,
        )?;

        Ok(Self {
            harness_fn,
            exposed_executor_state,
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
    ///
    /// This may return an error on unix, if signal handler setup fails
    pub fn with_timeout<EM, OF, Z>(
        harness_fn: &'a mut H,
        exposed_executor_state: ES,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, S::Input, OT, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
        <S as HasSolutions>::Solutions: Corpus<Input = S::Input>, //delete me
        <<S as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
    {
        let inner = GenericInProcessExecutorInner::with_timeout_generic::<Self, EM, OF, Z>(
            tuple_list!(),
            observers,
            fuzzer,
            state,
            event_mgr,
            timeout,
        )?;

        Ok(Self {
            harness_fn,
            exposed_executor_state,
            inner,
            phantom: PhantomData,
        })
    }
}

impl<H, HB, HT, OT, S, ES> StatefulGenericInProcessExecutor<H, HB, HT, OT, S, ES>
where
    H: FnMut(&mut ES, &mut S, &S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    /// The executor state given to the harness
    pub fn exposed_executor_state(&self) -> &ES {
        &self.exposed_executor_state
    }

    /// The mutable executor state given to the harness
    pub fn exposed_executor_state_mut(&mut self) -> &mut ES {
        &mut self.exposed_executor_state
    }
}

impl<H, HB, HT, OT, S, ES> StatefulGenericInProcessExecutor<H, HB, HT, OT, S, ES>
where
    H: FnMut(&mut ES, &mut S, &S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasExecutions + HasSolutions + HasCorpus,
    <S as HasSolutions>::Solutions: Corpus<Input = S::Input>, //delete me
    <<S as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
{
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        exposed_executor_state: ES,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, S::Input, OT, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        Self::with_timeout_generic(
            user_hooks,
            harness_fn,
            exposed_executor_state,
            observers,
            fuzzer,
            state,
            event_mgr,
            Duration::from_millis(5000),
        )
    }

    /// Create a new in mem executor with the default timeout and use batch mode(5 sec)
    #[cfg(all(feature = "std", target_os = "linux"))]
    #[allow(clippy::too_many_arguments)]
    pub fn batched_timeout_generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        exposed_executor_state: ES,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, S::Input, OT, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
        <S as HasSolutions>::Solutions: Corpus<Input = S::Input>, //delete me
        <<S as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
    {
        let inner = GenericInProcessExecutorInner::batched_timeout_generic::<Self, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, exec_tmout,
        )?;

        Ok(Self {
            harness_fn,
            exposed_executor_state,
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
    ///
    /// This may return an error on unix, if signal handler setup fails
    #[allow(clippy::too_many_arguments)]
    pub fn with_timeout_generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        exposed_executor_state: ES,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, S::Input, OT, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
        <S as HasSolutions>::Solutions: Corpus<Input = S::Input>, //delete me
        <<S as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
    {
        let inner = GenericInProcessExecutorInner::with_timeout_generic::<Self, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, timeout,
        )?;

        Ok(Self {
            harness_fn,
            exposed_executor_state,
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
    pub fn hooks(&self) -> &(InProcessHooks<S>, HT) {
        self.inner.hooks()
    }

    /// The inprocess handlers (mutable)
    #[inline]
    pub fn hooks_mut(&mut self) -> &mut (InProcessHooks<S>, HT) {
        self.inner.hooks_mut()
    }
}

impl<H, HB, HT, OT, S, ES> HasInProcessHooks<S>
    for StatefulGenericInProcessExecutor<H, HB, HT, OT, S, ES>
where
    H: FnMut(&mut ES, &mut S, &<S as UsesInput>::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasExecutions + HasSolutions + HasCorpus,
{
    /// the timeout handler
    #[inline]
    fn inprocess_hooks(&self) -> &InProcessHooks<S> {
        self.inner.inprocess_hooks()
    }

    /// the timeout handler
    #[inline]
    fn inprocess_hooks_mut(&mut self) -> &mut InProcessHooks<S> {
        self.inner.inprocess_hooks_mut()
    }
}
