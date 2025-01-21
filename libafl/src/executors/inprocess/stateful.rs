use alloc::boxed::Box;
use core::{
    borrow::BorrowMut,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    time::Duration,
};

use libafl_bolts::tuples::{tuple_list, RefIndexable};

use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::{inprocess::InProcessHooks, ExecutorHooksTuple},
        inprocess::GenericInProcessExecutorInner,
        EntersTarget, Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasCurrentTestcase, HasExecutions, HasSolutions},
    Error,
};

/// The process executor simply calls a target function, as mutable reference to a closure
/// The internal state of the executor is made available to the harness.
pub type StatefulInProcessExecutor<'a, ES, H, I, OT, S> =
    StatefulGenericInProcessExecutor<ES, H, &'a mut H, (), I, OT, S>;

/// The process executor simply calls a target function, as boxed `FnMut` trait object
/// The internal state of the executor is made available to the harness.
pub type OwnedInProcessExecutor<I, OT, S, ES> = StatefulGenericInProcessExecutor<
    dyn FnMut(&mut ES, &I) -> ExitKind,
    Box<dyn FnMut(&mut ES, &I) -> ExitKind>,
    (),
    I,
    OT,
    S,
    ES,
>;

/// The inmem executor simply calls a target function, then returns afterwards.
/// The harness can access the internal state of the executor.
pub struct StatefulGenericInProcessExecutor<ES, H, HB, HT, I, OT, S> {
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: Option<HB>,
    /// The state used as argument of the harness
    exposed_executor_state: Option<ES>,
    /// Inner state of the executor
    inner: GenericInProcessExecutorInner<HT, OT>,
    phantom: PhantomData<(*const H, I, S)>,
}

impl<H, HB, HT, I, OT, S, ES> Debug for StatefulGenericInProcessExecutor<ES, H, HB, HT, I, OT, S>
where
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulGenericInProcessExecutor")
            .field("harness_fn", &"<fn>")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<EM, H, HB, HT, I, OT, S, Z, ES> Executor<EM, I, S, Z>
    for StatefulGenericInProcessExecutor<ES, H, HB, HT, I, OT, S>
where
    H: FnMut(&mut ES, &I) -> ExitKind + Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<I, S>,
    OT: ObserversTuple<I, S>,
    S: HasExecutions,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        self.inner.hooks.pre_exec_all(state, input);
        let Some(mut harness_fn) = self.harness_fn.take() else {
            return Err(Error::illegal_state("We attempted to call the target without a harness function. This indicates that we somehow called the harness again from within the panic handler."));
        };
        let Some(mut exposed_executor_state) = self.exposed_executor_state.take() else {
            return Err(Error::illegal_state("We attempted to call the target without a harness function. This indicates that we somehow called the harness again from within the panic handler."));
        };
        let guard =
            GenericInProcessExecutorInner::<HT, OT>::enter_target(self, fuzzer, state, mgr, input);

        let ret = harness_fn.borrow_mut()(&mut exposed_executor_state, input);
        drop(guard);

        self.harness_fn = Some(harness_fn);
        self.exposed_executor_state = Some(exposed_executor_state);
        self.inner.hooks.post_exec_all(state, input);
        Ok(ret)
    }
}

impl<H, HB, HT, I, OT, S, ES> HasObservers
    for StatefulGenericInProcessExecutor<ES, H, HB, HT, I, OT, S>
where
    H: FnMut(&mut ES, &I) -> ExitKind + Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<I, S>,
    OT: ObserversTuple<I, S>,
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

impl<'a, H, I, OT, S, ES> StatefulInProcessExecutor<'a, ES, H, I, OT, S>
where
    H: FnMut(&mut ES, &I) -> ExitKind + Sized,
    OT: ObserversTuple<I, S>,
    S: HasExecutions + HasSolutions<I> + HasCurrentTestcase<I>,
    I: Clone + Input,
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
        EM: EventFirer<I, S> + EventRestarter<S>,
        OF: Feedback<EM, I, OT, S>,
        Z: HasObjective<Objective = OF>,
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
        EM: EventFirer<I, S> + EventRestarter<S>,
        OF: Feedback<EM, I, OT, S>,
        Z: HasObjective<Objective = OF>,
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
            harness_fn: Some(harness_fn),
            exposed_executor_state: Some(exposed_executor_state),
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
        EM: EventFirer<I, S> + EventRestarter<S>,
        OF: Feedback<EM, I, OT, S>,
        Z: HasObjective<Objective = OF>,
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
            harness_fn: Some(harness_fn),
            exposed_executor_state: Some(exposed_executor_state),
            inner,
            phantom: PhantomData,
        })
    }
}

impl<H, HB, HT, I, OT, S, ES> StatefulGenericInProcessExecutor<ES, H, HB, HT, I, OT, S> {
    /// The executor state given to the harness
    pub fn exposed_executor_state(&self) -> Option<&ES> {
        self.exposed_executor_state.as_ref()
    }

    /// The mutable executor state given to the harness
    pub fn exposed_executor_state_mut(&mut self) -> Option<&mut ES> {
        self.exposed_executor_state.as_mut()
    }
}

impl<H, HB, HT, I, OT, S, ES> StatefulGenericInProcessExecutor<ES, H, HB, HT, I, OT, S>
where
    H: FnMut(&mut ES, &I) -> ExitKind + Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<I, S>,
    I: Input + Clone,
    OT: ObserversTuple<I, S>,
    S: HasExecutions + HasSolutions<I> + HasCurrentTestcase<I>,
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
        EM: EventFirer<I, S> + EventRestarter<S>,
        OF: Feedback<EM, I, OT, S>,
        Z: HasObjective<Objective = OF>,
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
    #[expect(clippy::too_many_arguments)]
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
        EM: EventFirer<I, S> + EventRestarter<S>,
        OF: Feedback<EM, I, OT, S>,
        Z: HasObjective<Objective = OF>,
    {
        let inner = GenericInProcessExecutorInner::batched_timeout_generic::<Self, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, exec_tmout,
        )?;

        Ok(Self {
            harness_fn: Some(harness_fn),
            exposed_executor_state: Some(exposed_executor_state),
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
    #[expect(clippy::too_many_arguments)]
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
        EM: EventFirer<I, S> + EventRestarter<S>,
        OF: Feedback<EM, I, OT, S>,
        Z: HasObjective<Objective = OF>,
    {
        let inner = GenericInProcessExecutorInner::with_timeout_generic::<Self, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, timeout,
        )?;

        Ok(Self {
            harness_fn: Some(harness_fn),
            exposed_executor_state: Some(exposed_executor_state),
            inner,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> Option<&H> {
        self.harness_fn.as_ref().map(|h| h.borrow())
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> Option<&mut H> {
        self.harness_fn.as_mut().map(|h| h.borrow_mut())
    }

    /// The inprocess handlers
    #[inline]
    pub fn hooks(&self) -> &(InProcessHooks<I, S>, HT) {
        self.inner.hooks()
    }

    /// The inprocess handlers (mutable)
    #[inline]
    pub fn hooks_mut(&mut self) -> &mut (InProcessHooks<I, S>, HT) {
        self.inner.hooks_mut()
    }
}
