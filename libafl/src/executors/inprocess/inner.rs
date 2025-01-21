use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr::{self, null, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};

use libafl_bolts::tuples::RefIndexable;
#[cfg(windows)]
use windows::Win32::System::Threading::SetThreadStackGuarantee;

#[cfg(all(windows, feature = "std"))]
use crate::executors::hooks::inprocess::HasTimeout;
use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::{
            inprocess::GLOBAL_STATE, timer::TimerStruct, unix::unix_signal_handler,
            InitableExecutorHooksTuple,
        },
        EntersTarget, Executor, HasObservers,
    },
    feedbacks::Feedback,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasCurrentTestcase, HasExecutions, HasSolutions},
    Error, HasObjective,
};

/// The internal state of `GenericInProcessExecutor`.
pub struct GenericInProcessExecutorInner<HT, OT> {
    /// The observers, observing each run
    pub(super) observers: OT,
    // Crash and timeout hah
    pub(super) hooks: HT,
}

impl<HT, OT> Debug for GenericInProcessExecutorInner<HT, OT>
where
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessExecutorState")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl<HT, OT> HasObservers for GenericInProcessExecutorInner<HT, OT> {
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

/// A simple guard, to be used with [`GenericInProcessExecutorInner`].
#[derive(Debug)]
pub struct InProcessGuard<'a> {
    phantom: PhantomData<&'a ()>,
}

impl Drop for InProcessGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            let data = &raw mut GLOBAL_STATE;

            write_volatile(&raw mut (*data).timeout_handler, null());
            write_volatile(&raw mut (*data).crash_handler, null());
            write_volatile(&raw mut (*data).current_input_ptr, null());

            compiler_fence(Ordering::SeqCst);
        }
    }
}

impl<E, EM, HT, I, OT, S, Z> EntersTarget<E, EM, I, S, Z> for GenericInProcessExecutorInner<HT, OT>
where
    E: Executor<EM, I, S, Z> + HasObservers,
    E::Observers: ObserversTuple<I, S>,
    EM: EventFirer<I, S> + EventRestarter<S>,
    S: HasExecutions + HasSolutions<I> + HasCurrentTestcase<I>,
    Z: HasObjective,
    Z::Objective: Feedback<EM, I, E::Observers, S>,
    I: Input + Clone,
{
    type Guard<'a>
        = InProcessGuard<'a>
    where
        E: 'a,
        EM: 'a,
        I: 'a,
        S: 'a,
        Z: 'a;

    /// This function marks the boundary between the fuzzer and the target
    ///
    /// # Safety
    /// This function sets a bunch of raw pointers in global variables, reused in other parts of
    /// the code.
    #[inline]
    fn enter_target<'a>(
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Self::Guard<'a> {
        unsafe {
            let data = &raw mut GLOBAL_STATE;
            write_volatile(
                &raw mut (*data).current_input_ptr,
                ptr::from_ref(input) as *const c_void,
            );
            write_volatile(
                &raw mut (*data).executor_ptr,
                ptr::from_mut(executor) as *mut c_void,
            );
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(
                &raw mut (*data).state_ptr,
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
            write_volatile(
                &raw mut (*data).crash_handler,
                unix_signal_handler::inproc_crash_handler::<E, EM, I, S, Z> as *mut c_void,
            );
            write_volatile(
                &raw mut (*data).timeout_handler,
                unix_signal_handler::inproc_timeout_handler::<E, EM, I, S, Z> as *mut c_void,
            );

            // TODO should this be not(any(...))? Why would we only not run with miri on apple?
            #[cfg(all(feature = "std", not(all(miri, target_vendor = "apple"))))]
            if let Some(timer) = (*data).timer.as_mut() {
                timer.set_timer();
            }

            compiler_fence(Ordering::SeqCst);
        }
        InProcessGuard {
            phantom: PhantomData,
        }
    }
}

impl<HT, OT> GenericInProcessExecutorInner<HT, OT> {
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn generic<E, EM, S, Z>(
        user_hooks: HT,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        HT: InitableExecutorHooksTuple<S>,
    {
        Self::with_timeout_generic::<E, EM, S, Z>(
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
    pub fn batched_timeout_generic<E, EM, S, Z>(
        user_hooks: HT,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        HT: InitableExecutorHooksTuple<S>,
    {
        let me = Self::with_timeout_generic::<E, EM, S, Z>(
            user_hooks, observers, fuzzer, state, event_mgr, exec_tmout,
        )?;
        unsafe {
            let data = &raw mut GLOBAL_STATE;
            (*data).timer.as_mut().unwrap().batch_mode = true;
        }
        compiler_fence(Ordering::SeqCst);

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
    pub fn with_timeout_generic<E, EM, S, Z>(
        mut hooks: HT,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        HT: InitableExecutorHooksTuple<S>,
    {
        // # Safety
        // We get a pointer to `GLOBAL_STATE` that will be initialized at this point in time.
        // This unsafe is needed in stable but not in nightly. Remove in the future(?)
        #[expect(unused_unsafe)]
        #[cfg(all(not(miri), unix, feature = "std"))]
        let data = unsafe { &raw mut GLOBAL_STATE };
        // # Safety
        // Setting up the signal handlers with a pointer to the `GLOBAL_STATE` which should not be NULL at this point.
        // We are the sole users of `GLOBAL_STATE` right now, and only dereference it in case of Segfault/Panic.
        // In that case we get the mutable borrow. Otherwise we don't use it.
        #[cfg(all(not(miri), unix, feature = "std"))]
        unsafe {
            libafl_bolts::os::unix_signals::setup_signal_handler(data)?;
            (*data).timer = Some(TimerStruct::new(timeout));
        }
        compiler_fence(Ordering::SeqCst);

        #[cfg(feature = "std")]
        unix_signal_handler::setup_panic_hook();
        hooks.init_all(state);

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

        Ok(Self { observers, hooks })
    }

    /// The inprocess handlers
    #[inline]
    pub fn hooks(&self) -> &HT {
        &self.hooks
    }

    /// The inprocess handlers (mutable)
    #[inline]
    pub fn hooks_mut(&mut self) -> &mut HT {
        &mut self.hooks
    }
}
