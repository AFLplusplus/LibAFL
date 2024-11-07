//! The [`InProcessExecutor`] is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.
//!
//! Needs the `fork` feature flag.
#![allow(clippy::needless_pass_by_value)]

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

#[cfg(any(unix, feature = "std"))]
use crate::executors::hooks::inprocess::GLOBAL_STATE;
use crate::{
    corpus::{Corpus, Testcase},
    events::{Event, EventFirer, EventRestarter},
    executors::{
        hooks::{inprocess::InProcessHooks, ExecutorHooksTuple},
        inprocess::inner::GenericInProcessExecutorInner,
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::ObserversTuple,
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasSolutions, State, UsesState},
    Error, HasMetadata,
};
#[cfg(any(unix, feature = "std"))]
use crate::{ExecutionProcessor, HasScheduler};

/// The inner structure of `InProcessExecutor`.
pub mod inner;
/// A version of `InProcessExecutor` with a state accessible from the harness.
pub mod stateful;

/// The process executor simply calls a target function, as mutable reference to a closure.
pub type InProcessExecutor<'a, H, OT, S> = GenericInProcessExecutor<H, &'a mut H, (), OT, S>;

/// The inprocess executor that allows hooks
pub type HookableInProcessExecutor<'a, H, HT, OT, S> =
    GenericInProcessExecutor<H, &'a mut H, HT, OT, S>;
/// The process executor simply calls a target function, as boxed `FnMut` trait object
pub type OwnedInProcessExecutor<OT, S> = GenericInProcessExecutor<
    dyn FnMut(&<S as UsesInput>::Input) -> ExitKind,
    Box<dyn FnMut(&<S as UsesInput>::Input) -> ExitKind>,
    (),
    OT,
    S,
>;

/// The inmem executor simply calls a target function, then returns afterwards.
#[allow(dead_code)]
pub struct GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    harness_fn: HB,
    inner: GenericInProcessExecutorInner<HT, OT, S>,
    phantom: PhantomData<(*const H, HB)>,
}

impl<H, HB, HT, OT, S> Debug for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S> + Debug,
    S: State,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessExecutor")
            .field("inner", &self.inner)
            .field("harness_fn", &"<fn>")
            .finish_non_exhaustive()
    }
}

impl<H, HB, HT, OT, S> UsesState for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    type State = S;
}

impl<EM, H, HB, HT, OT, S, Z> Executor<EM, Z> for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    EM: UsesState<State = S>,
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
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

        let ret = self.harness_fn.borrow_mut()(input);

        self.inner.hooks.post_exec_all(state, input);
        self.inner.leave_target(fuzzer, state, mgr, input);
        Ok(ret)
    }
}

impl<H, HB, HT, OT, S> HasObservers for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
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

impl<'a, H, OT, S> InProcessExecutor<'a, H, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: HasExecutions + HasSolutions + HasCorpus + State,
    <S as HasSolutions>::Solutions: Corpus<Input = S::Input>, //delete me
    <<S as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
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
        Self: Executor<EM, Z, State = S> + HasObservers,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, S::Input, OT, S>,
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
    pub fn batched_timeout<EM, OF, Z>(
        harness_fn: &'a mut H,
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
            inner,
            phantom: PhantomData,
        })
    }
}

impl<H, HB, HT, OT, S> GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
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
        Self: Executor<EM, Z, State = S>,
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
            inner,
            phantom: PhantomData,
        })
    }

    /// Create a new [`InProcessExecutor`].
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `user_hooks` - the hooks run before and after the harness's execution
    /// * `harness_fn` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    ///
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
        Self: Executor<EM, Z, State = S>,
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

/// The struct has [`InProcessHooks`].
pub trait HasInProcessHooks<S>
where
    S: UsesInput,
{
    /// Get the in-process handlers.
    fn inprocess_hooks(&self) -> &InProcessHooks<S>;

    /// Get the mut in-process handlers.
    fn inprocess_hooks_mut(&mut self) -> &mut InProcessHooks<S>;
}

impl<H, HB, HT, OT, S> HasInProcessHooks<S> for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&<S as UsesInput>::Input) -> ExitKind + ?Sized,
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

#[inline]
#[allow(clippy::too_many_arguments)]
/// Save state if it is an objective
pub fn run_observers_and_save_state<E, EM, OF, Z>(
    executor: &mut E,
    state: &mut E::State,
    input: &E::Input,
    fuzzer: &mut Z,
    event_mgr: &mut EM,
    exitkind: ExitKind,
) where
    E: Executor<EM, Z> + HasObservers,
    E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<EM, E::Input, E::Observers, E::State>,
    E::State: HasExecutions + HasSolutions + HasCorpus + HasCurrentTestcase,
    Z: HasObjective<Objective = OF, State = E::State>,
    <<E as UsesState>::State as HasSolutions>::Solutions: Corpus<Input = E::Input>, //delete me
{
    let mut observers = executor.observers_mut();

    observers
        .post_exec_all(state, input, &exitkind)
        .expect("Observers post_exec_all failed");

    let interesting = fuzzer
        .objective_mut()
        .is_interesting(state, event_mgr, input, &*observers, &exitkind)
        .expect("In run_observers_and_save_state objective failure.");

    if interesting {
        let mut new_testcase = Testcase::from(input.clone());
        new_testcase.add_metadata(exitkind);
        new_testcase.set_parent_id_optional(*state.corpus().current());

        if let Ok(mut tc) = state.current_testcase_mut() {
            tc.found_objective();
        }

        fuzzer
            .objective_mut()
            .append_metadata(state, event_mgr, &*observers, &mut new_testcase)
            .expect("Failed adding metadata");
        state
            .solutions_mut()
            .add(new_testcase)
            .expect("In run_observers_and_save_state solutions failure.");
        event_mgr
            .fire(
                state,
                Event::Objective {
                    objective_size: state.solutions().count(),
                    time: libafl_bolts::current_time(),
                },
            )
            .expect("Could not save state in run_observers_and_save_state");
    }

    // Serialize the state and wait safely for the broker to read pending messages
    event_mgr.on_restart(state).unwrap();

    log::info!("Bye!");
}

// TODO remove this after executor refactor and libafl qemu new executor
/// Expose a version of the crash handler that can be called from e.g. an emulator
///
/// # Safety
/// This will directly access `GLOBAL_STATE` and related data pointers
#[cfg(any(unix, feature = "std"))]
pub unsafe fn generic_inproc_crash_handler<E, EM, OF, Z>()
where
    E: Executor<EM, Z> + HasObservers,
    E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<EM, E::Input, E::Observers, E::State>,
    E::State: HasExecutions + HasSolutions + HasCorpus + HasCurrentTestcase,
    Z: HasObjective<Objective = OF, State = E::State>
        + HasScheduler<State = E::State>
        + ExecutionProcessor<EM, E::Observers>,
    <<E as UsesState>::State as HasSolutions>::Solutions: Corpus<Input = E::Input>, //delete me
{
    let data = &raw mut GLOBAL_STATE;
    let in_handler = (*data).set_in_handler(true);

    if (*data).is_valid() {
        let executor = (*data).executor_mut::<E>();
        let state = (*data).state_mut::<E::State>();
        let event_mgr = (*data).event_mgr_mut::<EM>();
        let fuzzer = (*data).fuzzer_mut::<Z>();
        let input = (*data).take_current_input::<<E::State as UsesInput>::Input>();

        run_observers_and_save_state::<E, EM, OF, Z>(
            executor,
            state,
            input,
            fuzzer,
            event_mgr,
            ExitKind::Crash,
        );
    }

    (*data).set_in_handler(in_handler);
}

#[cfg(test)]
mod tests {
    use libafl_bolts::tuples::tuple_list;

    use crate::{
        corpus::InMemoryCorpus,
        events::NopEventManager,
        executors::{Executor, ExitKind, InProcessExecutor},
        feedbacks::CrashFeedback,
        inputs::{NopInput, UsesInput},
        schedulers::RandScheduler,
        state::StdState,
        StdFuzzer,
    };

    impl UsesInput for () {
        type Input = NopInput;
    }

    #[test]
    #[allow(clippy::let_unit_value)]
    fn test_inmem_exec() {
        let mut harness = |_buf: &NopInput| ExitKind::Ok;
        let rand = libafl_bolts::rands::XkcdRand::new();
        let corpus = InMemoryCorpus::<NopInput>::new();
        let solutions = InMemoryCorpus::new();
        let mut objective = CrashFeedback::new();
        let mut feedback = tuple_list!();
        let sche = RandScheduler::new();
        let mut mgr = NopEventManager::new();
        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
        let mut fuzzer = StdFuzzer::<_, _, _, _>::new(sche, feedback, objective);

        let mut in_process_executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        let input = NopInput {};
        in_process_executor
            .run_target(&mut fuzzer, &mut state, &mut mgr, &input)
            .unwrap();
    }
}
