use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr::{self, null, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};

use libafl_bolts::tuples::{tuple_list, Merge, RefIndexable};
#[cfg(windows)]
use windows::Win32::System::Threading::SetThreadStackGuarantee;

#[cfg(all(feature = "std", target_os = "linux"))]
use crate::executors::hooks::inprocess::HasTimeout;
#[cfg(all(windows, feature = "std"))]
use crate::executors::hooks::inprocess::HasTimeout;
use crate::{
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::{
            inprocess::{InProcessHooks, GLOBAL_STATE},
            ExecutorHooksTuple,
        },
        inprocess::HasInProcessHooks,
        Executor, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::ObserversTuple,
    state::{HasCorpus, HasExecutions, HasSolutions, State, UsesState},
    Error,
};

/// The internal state of `GenericInProcessExecutor`.
pub struct GenericInProcessExecutorInner<HT, OT, S> {
    /// The observers, observing each run
    pub(super) observers: OT,
    // Crash and timeout hah
    pub(super) hooks: (InProcessHooks<S>, HT),
    phantom: PhantomData<S>,
}

impl<HT, OT, S> Debug for GenericInProcessExecutorInner<HT, OT, S>
where
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessExecutorState")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl<HT, OT, S> UsesState for GenericInProcessExecutorInner<HT, OT, S>
where
    S: State,
{
    type State = S;
}

impl<HT, OT, S> HasObservers for GenericInProcessExecutorInner<HT, OT, S>
where
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
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

impl<HT, OT, S> GenericInProcessExecutorInner<HT, OT, S>
where
    HT: ExecutorHooksTuple<S>,
    S: State,
{
    /// This function marks the boundary between the fuzzer and the target
    ///
    /// # Safety
    /// This function sets a bunch of raw pointers in global variables, reused in other parts of
    /// the code.
    #[inline]
    pub unsafe fn enter_target<EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        state: &mut <Self as UsesState>::State,
        mgr: &mut EM,
        input: &<Self as UsesInput>::Input,
        executor_ptr: *const c_void,
    ) {
        unsafe {
            let data = &raw mut GLOBAL_STATE;
            write_volatile(
                &raw mut (*data).current_input_ptr,
                ptr::from_ref(input) as *const c_void,
            );
            write_volatile(&raw mut (*data).executor_ptr, executor_ptr);
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(
                &raw mut ((*data).state_ptr),
                ptr::from_mut(state) as *mut c_void,
            );
            write_volatile(
                &raw mut (*data).event_mgr_ptr,
                ptr::from_mut(mgr) as *mut c_void,
            );
            write_volatile(
                &raw mut (*data).fuzzer_ptr,
                ptr::from_mut(fuzzer) as *mut c_void,
            );
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// This function marks the boundary between the fuzzer and the target
    #[inline]
    pub fn leave_target<EM, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut <Self as UsesState>::State,
        _mgr: &mut EM,
        _input: &<Self as UsesInput>::Input,
    ) {
        unsafe {
            let data = &raw mut GLOBAL_STATE;

            write_volatile(&raw mut (*data).current_input_ptr, null());
            compiler_fence(Ordering::SeqCst);
        }
    }
}

impl<HT, OT, S> GenericInProcessExecutorInner<HT, OT, S>
where
    HT: ExecutorHooksTuple<S>,
    OT: ObserversTuple<S::Input, S>,
    S: HasCorpus + HasExecutions + HasSolutions + UsesInput,
{
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn generic<E, EM, OF, Z>(
        user_hooks: HT,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        E: Executor<EM, Z, State = S> + HasObservers + HasInProcessHooks<S>,
        E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, E::Input, E::Observers, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
        <<E as UsesState>::State as HasSolutions>::Solutions: Corpus<Input = E::Input>, //delete me
        <<<E as UsesState>::State as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
    {
        Self::with_timeout_generic::<E, EM, OF, Z>(
            user_hooks,
            observers,
            fuzzer,
            state,
            event_mgr,
            Duration::from_millis(5000),
        )
    }

    /// Create a new in mem executor with the default timeout and use batch mode(5 sec)
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn batched_timeout_generic<E, EM, OF, Z>(
        user_hooks: HT,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        E: Executor<EM, Z, State = S> + HasObservers + HasInProcessHooks<S>,
        E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, E::Input, E::Observers, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
        <<E as UsesState>::State as HasSolutions>::Solutions: Corpus<Input = E::Input>, //delete me
        <<<E as UsesState>::State as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
    {
        let mut me = Self::with_timeout_generic::<E, EM, OF, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, exec_tmout,
        )?;
        me.hooks_mut().0.timer_mut().batch_mode = true;
        Ok(me)
    }

    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `user_hooks` - the hooks run before and after the harness's execution
    /// * `harness_fn` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    ///
    /// This may return an error on unix, if signal handler setup fails
    pub fn with_timeout_generic<E, EM, OF, Z>(
        user_hooks: HT,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        E: Executor<EM, Z, State = S> + HasObservers + HasInProcessHooks<S>,
        E::Observers: ObserversTuple<<E::State as UsesInput>::Input, E::State>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<EM, E::Input, E::Observers, S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
        <<E as UsesState>::State as HasSolutions>::Solutions: Corpus<Input = E::Input>, //delete me
        <<<E as UsesState>::State as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
    {
        let default = InProcessHooks::new::<E, EM, OF, Z>(timeout)?;
        let mut hooks = tuple_list!(default).merge(user_hooks);
        hooks.init_all::<Self>(state);

        #[cfg(windows)]
        // Some initialization necessary for windows.
        unsafe {
            /*
                See https://github.com/AFLplusplus/LibAFL/pull/403
                This one reserves certain amount of memory for the stack.
                If stack overflow happens during fuzzing on windows, the program is transferred to our exception handler for windows.
                However, if we run out of the stack memory again in this exception handler, we'll crash with STATUS_ACCESS_VIOLATION.
                We need this API call because with the llmp_compression
                feature enabled, the exception handler uses a lot of stack memory (in the compression lib code) on release build.
                As far as I have observed, the compression uses around 0x10000 bytes, but for safety let's just reserve 0x20000 bytes for our exception handlers.
                This number 0x20000 could vary depending on the compilers optimization for future compression library changes.
            */
            let mut stack_reserved = 0x20000;
            SetThreadStackGuarantee(&mut stack_reserved)?;
        }

        #[cfg(all(feature = "std", windows))]
        {
            // set timeout for the handler
            *hooks.0.millis_sec_mut() = timeout.as_millis() as i64;
        }

        Ok(Self {
            observers,
            hooks,
            phantom: PhantomData,
        })
    }

    /// The inprocess handlers
    #[inline]
    pub fn hooks(&self) -> &(InProcessHooks<S>, HT) {
        &self.hooks
    }

    /// The inprocess handlers (mutable)
    #[inline]
    pub fn hooks_mut(&mut self) -> &mut (InProcessHooks<S>, HT) {
        &mut self.hooks
    }
}

impl<HT, OT, S> HasInProcessHooks<S> for GenericInProcessExecutorInner<HT, OT, S>
where
    S: UsesInput,
{
    /// the timeout handler
    #[inline]
    fn inprocess_hooks(&self) -> &InProcessHooks<S> {
        &self.hooks.0
    }

    /// the timeout handler
    #[inline]
    fn inprocess_hooks_mut(&mut self) -> &mut InProcessHooks<S> {
        &mut self.hooks.0
    }
}
