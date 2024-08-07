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
    ptr::{addr_of_mut, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};

use libafl_bolts::tuples::{tuple_list, RefIndexable};

#[cfg(any(unix, feature = "std"))]
use crate::executors::hooks::inprocess::GLOBAL_STATE;
use crate::{
    corpus::HasCorpus,
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::{inprocess::InProcessHooks, ExecutorHook, ExecutorHooksTuple},
        inprocess::inner::GenericInProcessExecutorInner,
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    observers::ObserversTuple,
    schedulers::Scheduler,
    state::{HasExecutions, HasSolutions},
    Error, ExecutionProcessor, HasScheduler,
};

/// The inner structure of `InProcessExecutor`.
pub mod inner;
/// A version of `InProcessExecutor` with a state accessible from the harness.
pub mod stateful;

/// A harness which exercises the target
pub trait Harness<I> {
    fn run(&mut self, input: &I) -> ExitKind;
}

/// The process executor simply calls a target function, as mutable reference to a closure.
pub type InProcessExecutor<H, OT> = GenericInProcessExecutor<H, (), OT>;

/// The inmem executor simply calls a target function, then returns afterward.
#[allow(dead_code)]
pub struct GenericInProcessExecutor<H, HT, OT> {
    harness: H,
    hooks: Option<HT>,
    observers: OT,
}

impl<H, HT, OT> Debug for GenericInProcessExecutor<H, HT, OT>
where
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessExecutor")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl<H, HT, OT> HasObservers for GenericInProcessExecutor<H, HT, OT> {
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

#[derive(Debug)]
pub struct RecoveryHook;

impl<E, EM, I, S, Z> ExecutorHook<E, EM, I, S, Z> for RecoveryHook {
    fn pre_exec(
        &mut self,
        executor: &mut E,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S,
    ) {
        todo!()
    }

    fn post_exec(
        &mut self,
        executor: &mut E,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S,
    ) {
        todo!()
    }
}

/// This function marks the boundary between the fuzzer and the target for in-process executors
///
/// # Safety
/// This function sets a bunch of raw pointers in global variables, reused in other parts of
/// the code.
#[inline]
pub fn enter_target<EM, I, S, Z>(
    fuzzer: &mut Z,
    state: &mut S,
    mgr: &mut EM,
    input: &S,
    executor_ptr: *const c_void,
) {
    unsafe {
        let data = addr_of_mut!(GLOBAL_STATE);
        write_volatile(
            addr_of_mut!((*data).current_input_ptr),
            ptr::from_ref(input) as *const c_void,
        );
        write_volatile(addr_of_mut!((*data).executor_ptr), executor_ptr);
        // Direct raw pointers access /aliasing is pretty undefined behavior.
        // Since the state and event may have moved in memory, refresh them right before the signal may happen
        write_volatile(
            addr_of_mut!((*data).state_ptr),
            ptr::from_mut(state) as *mut c_void,
        );
        write_volatile(
            addr_of_mut!((*data).event_mgr_ptr),
            ptr::from_mut(mgr) as *mut c_void,
        );
        write_volatile(
            addr_of_mut!((*data).fuzzer_ptr),
            ptr::from_mut(fuzzer) as *mut c_void,
        );
        compiler_fence(Ordering::SeqCst);
    }
}

/// This function marks the boundary between the fuzzer and the target
#[inline]
pub fn leave_target() {
    unsafe {
        let data = addr_of_mut!(GLOBAL_STATE);

        write_volatile(addr_of_mut!((*data).current_input_ptr), ptr::null());
        compiler_fence(Ordering::SeqCst);
    }
}

impl<EM, H, HT, I, OT, S, Z> Executor<EM, I, S, Z> for GenericInProcessExecutor<H, HT, OT>
where
    H: Harness<I>,
    HT: ExecutorHooksTuple<Self, EM, I, S, Z>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;
        unsafe {
            let executor_ptr = ptr::from_ref(self) as *const c_void;
            enter_target(fuzzer, state, mgr, input, executor_ptr);
        }
        self.hooks.pre_exec_all(state, input);

        let ret = self.harness.run(input);

        self.hooks.post_exec_all(state, input);
        leave_target();
        Ok(ret)
    }
}

impl<H, OT> InProcessExecutor<H, OT> {
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn new<EM, S, Z>(
        harness: H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error> {
        Self::with_timeout_generic(
            tuple_list!(),
            harness,
            observers,
            fuzzer,
            state,
            event_mgr,
            Duration::from_millis(5000),
        )
    }

    /// Create a new in mem executor with the default timeout and use batch mode(5 sec)
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn batched_timeout<EM, S, Z>(
        harness: H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error> {
        Ok(Self {
            harness,
            inner,
            phantom: PhantomData,
        })
    }

    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `user_hooks` - the hooks run before and after the harness's execution
    /// * `harness` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    ///
    /// This may return an error on unix, if signal handler setup fails
    pub fn with_timeout<EM, OF, Z>(
        harness: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S> + HasScheduler + ExecutionProcessor,
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
            harness,
            inner,
            phantom: PhantomData,
        })
    }
}

impl<H, HT, OT> GenericInProcessExecutor<H, HT, OT>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S>,
    S: State + HasExecutions + HasSolutions + HasCorpus,
{
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn generic<EM, OF, Z>(
        user_hooks: HT,
        harness: HB,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S> + HasScheduler + ExecutionProcessor,
    {
        Self::with_timeout_generic(
            user_hooks,
            harness,
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
        harness: HB,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S> + HasScheduler + ExecutionProcessor,
    {
        let inner = GenericInProcessExecutorInner::batched_timeout_generic::<Self, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, exec_tmout,
        )?;

        Ok(Self {
            harness,
            inner,
            phantom: PhantomData,
        })
    }

    /// Create a new [`InProcessExecutor`].
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `user_hooks` - the hooks run before and after the harness's execution
    /// * `harness` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    ///
    /// This may return an error on unix, if signal handler setup fails
    pub fn with_timeout_generic<EM, OF, Z>(
        user_hooks: HT,
        harness: HB,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S> + HasScheduler + ExecutionProcessor,
    {
        let inner = GenericInProcessExecutorInner::with_timeout_generic::<Self, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, timeout,
        )?;

        Ok(Self {
            harness,
            inner,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness.borrow()
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness.borrow_mut()
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

// TODO remove this after executor refactor and libafl qemu new executor
/// Expose a version of the crash handler that can be called from e.g. an emulator
///
/// # Safety
/// This will directly access `GLOBAL_STATE` and related data pointers
#[cfg(any(unix, feature = "std"))]
pub unsafe fn generic_inproc_crash_handler<E, EM, OF, Z>()
where
    E: Executor<EM, Z> + HasObservers,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasExecutions + HasSolutions + HasCorpus,
    Z: HasObjective<Objective = OF, State = E::State>
        + HasScheduler<State = E::State>
        + ExecutionProcessor,
{
    let data = addr_of_mut!(GLOBAL_STATE);
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
        let mut fuzzer = StdFuzzer::<_, _, _>::new(sche, feedback, objective);

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
