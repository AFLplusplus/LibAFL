//! The hook for `InProcessExecutor`

use alloc::boxed::Box;
use core::{
    ffi::c_void,
    marker::PhantomData,
    sync::atomic::{AtomicPtr, Ordering},
};

use crate::{
    corpus::{Corpus, HasCorpus},
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::{ExecutorHook, HookContext},
        ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    schedulers::Scheduler,
    state::{HasExecutions, HasSolutions},
    Error, ExecutionProcessor, HasObjective, HasScheduler,
};

/// In-process hooks which install global handlers by safely lifting the local execution context
/// into a global variable during execution.
///
/// Callbacks registered with this hook are guaranteed to have *exclusive mutable access* to
/// context data. If a handler is triggered during the execution of another handler, it will not be
/// executed as the global variable is atomically swapped with empty data during handler execution.
///
/// This means, for example, if you are installing a timeout handler that allows execution to
/// continue, and your timeout handler is executed during the handling of another event, the timeout
/// will be lost. For handlers which terminate execution, this is a non-issue.
#[allow(missing_debug_implementations)]
pub struct InProcessHook<H> {
    phantom_data: PhantomData<fn() -> H>,
}

impl<H> InProcessHook<H> {
    /// Create a new [`InProcessHook`]. You will likely want to call this function from an alias
    pub fn new() -> Self {
        Self {
            phantom_data: PhantomData,
        }
    }
}

// impl<E> HasTimeout for InProcessHooks<E> {
//     #[cfg(feature = "std")]
//     fn timer(&self) -> &TimerStruct {
//         &self.timer
//     }
//     #[cfg(feature = "std")]
//     fn timer_mut(&mut self) -> &mut TimerStruct {
//         &mut self.timer
//     }
//
//     #[cfg(all(feature = "std", windows))]
//     fn ptp_timer(&self) -> &PTP_TIMER {
//         self.timer().ptp_timer()
//     }
//
//     #[cfg(all(feature = "std", windows))]
//     fn critical(&self) -> &CRITICAL_SECTION {
//         self.timer().critical()
//     }
//
//     #[cfg(all(feature = "std", windows))]
//     fn critical_mut(&mut self) -> &mut CRITICAL_SECTION {
//         self.timer_mut().critical_mut()
//     }
//
//     #[cfg(all(feature = "std", windows))]
//     fn milli_sec(&self) -> i64 {
//         self.timer().milli_sec()
//     }
//
//     #[cfg(all(feature = "std", windows))]
//     fn millis_sec_mut(&mut self) -> &mut i64 {
//         self.timer_mut().milli_sec_mut()
//     }
//
//     #[cfg(not(all(unix, feature = "std")))]
//     fn handle_timeout(&mut self) -> bool {
//         false
//     }
//
//     #[cfg(all(unix, feature = "std"))]
//     #[allow(unused)]
//     fn handle_timeout(&mut self, data: &mut InProcessExecutorHandlerData) -> bool {
//         #[cfg(not(target_os = "linux"))]
//         {
//             false
//         }
//
//         #[cfg(target_os = "linux")]
//         {
//             if !self.timer().batch_mode {
//                 return false;
//             }
//             //eprintln!("handle_timeout {:?} {}", self.avg_exec_time, self.avg_mul_k);
//             let cur_time = current_time();
//             if !data.is_valid() {
//                 // outside the target
//                 unsafe {
//                     let disarmed: libc::itimerspec = zeroed();
//                     libc::timer_settime(
//                         self.timer_mut().timerid,
//                         0,
//                         addr_of!(disarmed),
//                         null_mut(),
//                     );
//                 }
//                 let elapsed = cur_time - self.timer().tmout_start_time;
//                 // set timer the next exec
//                 if self.timer().executions > 0 {
//                     self.timer_mut().avg_exec_time = elapsed / self.timer().executions;
//                     self.timer_mut().executions = 0;
//                 }
//                 self.timer_mut().avg_mul_k += 1;
//                 self.timer_mut().last_signal_time = cur_time;
//                 return true;
//             }
//
//             let elapsed_run = cur_time - self.timer_mut().start_time;
//             if elapsed_run < self.timer_mut().exec_tmout {
//                 // fp, reset timeout
//                 unsafe {
//                     libc::timer_settime(
//                         self.timer_mut().timerid,
//                         0,
//                         addr_of!(self.timer_mut().itimerspec),
//                         null_mut(),
//                     );
//                 }
//                 if self.timer().executions > 0 {
//                     let elapsed = cur_time - self.timer_mut().tmout_start_time;
//                     self.timer_mut().avg_exec_time = elapsed / self.timer().executions;
//                     self.timer_mut().executions = 0; // It will be 1 when the exec finish
//                 }
//                 self.timer_mut().tmout_start_time = current_time();
//                 self.timer_mut().avg_mul_k += 1;
//                 self.timer_mut().last_signal_time = cur_time;
//                 true
//             } else {
//                 false
//             }
//         }
//     }
// }

/// Handle an event with the corresponding data, as retrieved from the global context
pub trait InProcessHookHandler<C> {
    /// Install the handler as appropriate for this platform
    fn install() -> Result<(), Error>;
    /// Uninstall the handler
    fn uninstall() -> Result<(), Error>;
}

/// Data trait for tracking fixed content in [`GlobalContextGuard`], to reduce some generics
pub trait InProcessGlobalContext {
    /// The executor stored in the global context
    type Executor;
    /// The event manager stored in the global context
    type EventManager;
    /// The input stored in the global context
    type Input;
    /// The state stored in the global context
    type State;
    /// The fuzzer stored in the global context
    type Fuzzer;
}

/// Utility trait for saving state; just use `impl InProcessStateSaver` for functions and
/// `GlobalContextGuard<'a, E, EM, I, S, Z>: InProcessStateSaver` when handling the guard directly.
pub trait InProcessStateSaver: InProcessGlobalContext {
    /// Process the results of an execution in the case of an event that triggers the end of execution
    /// (e.g., a timeout or a crash). You must still terminate the process yourself.
    fn run_observers_and_save_state(&mut self, exit_kind: ExitKind);
}

/// Guard for the global context. When this guard exists, the global context is stored within. On
/// drop (e.g., when exiting scope), the context is returned to global availability. This ensures
/// exclusive mutable access to the execution context.
#[derive(Debug)]
pub struct GlobalContextGuard<'a, E, EM, I, S, Z> {
    ctx: &'a mut ExecutionContextData,
    phantom: PhantomData<fn() -> (E, EM, I, S, Z)>,
}

impl<'a, E, EM, I, S, Z> InProcessGlobalContext for GlobalContextGuard<'a, E, EM, I, S, Z> {
    type Executor = E;
    type EventManager = EM;
    type Input = I;
    type State = S;
    type Fuzzer = Z;
}

impl<'a, E, EM, S, Z> InProcessStateSaver
    for GlobalContextGuard<'a, E, EM, <S::Corpus as Corpus>::Input, S, Z>
where
    E: HasObservers,
    EM: EventFirer<<S::Corpus as Corpus>::Input, S> + EventRestarter<S>,
    S: HasExecutions + HasSolutions + HasCorpus,
    S::Solutions: Corpus<Input = <S::Corpus as Corpus>::Input>,
    <S::Corpus as Corpus>::Input: Clone,
    Z: HasObjective
        + HasScheduler
        + ExecutionProcessor<EM, <S::Corpus as Corpus>::Input, E::Observers, S>,
    Z::Scheduler: Scheduler<<S::Corpus as Corpus>::Input, E::Observers, S>,
    Z::Objective: Feedback<EM, <S::Corpus as Corpus>::Input, E::Observers, S>,
{
    #[inline]
    fn run_observers_and_save_state(&mut self, exit_kind: ExitKind) {
        let (executor, fuzzer, state, manager, input) = self.access();

        let observers = executor.observers_mut();
        let scheduler = fuzzer.scheduler_mut();

        if scheduler.on_evaluation(state, input, &*observers).is_err() {
            log::error!("Failed to call on_evaluation");
            return;
        }

        let res = fuzzer.check_results(state, manager, input, &*observers, &exit_kind);
        if let Ok(exec_res) = res {
            if fuzzer
                .process_execution(state, manager, input, &exec_res, &*observers)
                .is_err()
            {
                log::error!("Failed to call process_execution");
                return;
            }

            if fuzzer
                .dispatch_event(state, manager, input.clone(), &exec_res, None, &exit_kind)
                .is_err()
            {
                log::error!("Failed to dispatch_event");
                return;
            }
        } else {
            log::error!("Faild to check execution result");
        }
        // Serialize the state and wait safely for the broker to read pending messages
        manager.on_restart(state).unwrap();

        log::info!("Bye!");
    }
}

impl GlobalContextGuard<'static, (), (), (), (), ()> {
    /// Take the global context using the provided [`HookContext`]. You must call this function like
    /// `GlobalContextGuard::take_guard::<C>()`, with `C` as your context.
    ///
    /// ## Safety
    ///
    /// This function is marked unsafe because if you specify an invalid `C`, the types will
    /// certainly be wrong. Provided you appropriately specify `C`, this function is otherwise safe.
    pub unsafe fn take_global<'a, C>(
    ) -> Option<GlobalContextGuard<'a, C::Executor, C::EventManager, C::Input, C::State, C::Fuzzer>>
    where
        C: HookContext<'a>,
    {
        CONTEXT
            .swap(core::ptr::null_mut(), Ordering::Relaxed)
            .as_mut()
            .map(|ctx| GlobalContextGuard::<
                'a,
                C::Executor,
                C::EventManager,
                C::Input,
                C::State,
                C::Fuzzer,
            > {
                ctx,
                phantom: PhantomData,
            })
    }
}

impl<'a, E, EM, I, S, Z> GlobalContextGuard<'a, E, EM, I, S, Z> {
    /// Access the members of the global context.
    ///
    /// ## Safety
    ///
    /// This function internally accesses the global context, which involves casting the
    /// corresponding members of the context according to `C` of
    /// [`GlobalContextGuard::take_global`].
    pub fn access(&mut self) -> (&mut E, &mut Z, &mut S, &mut EM, &I) {
        unsafe {
            (
                self.ctx.executor(),
                self.ctx.fuzzer(),
                self.ctx.state(),
                self.ctx.manager(),
                self.ctx.input(),
            )
        }
    }
}

impl<'a, E, EM, I, S, Z> Drop for GlobalContextGuard<'a, E, EM, I, S, Z> {
    fn drop(&mut self) {
        CONTEXT.store(self.ctx, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct ExecutionContextData {
    executor: *mut c_void,
    fuzzer: *mut c_void,
    state: *mut c_void,
    mgr: *mut c_void,
    input: *const c_void,
}

impl ExecutionContextData {
    pub unsafe fn executor<'a, E>(&self) -> &'a mut E {
        &mut *(self.executor as *mut E)
    }
    pub unsafe fn fuzzer<'a, Z>(&self) -> &'a mut Z {
        &mut *(self.fuzzer as *mut Z)
    }
    pub unsafe fn state<'a, S>(&self) -> &'a mut S {
        &mut *(self.state as *mut S)
    }
    pub unsafe fn manager<'a, EM>(&self) -> &'a mut EM {
        &mut *(self.mgr as *mut EM)
    }
    pub unsafe fn input<'a, I>(&self) -> &'a I {
        &*(self.input as *const I)
    }
}

static CONTEXT: AtomicPtr<ExecutionContextData> = AtomicPtr::new(core::ptr::null_mut());

/// Context for [`InProcessHook`]s when the global execution context has been installed
#[derive(Debug)]
pub struct InProcessContext<C> {
    context: C,
}

impl<C> InProcessContext<C> {
    fn new(context: C) -> Self {
        Self { context }
    }
}

impl<'a, C, H> ExecutorHook<C> for InProcessHook<H>
where
    H: InProcessHookHandler<C>,
    C: HookContext<'a> + 'a,
{
    type Context = InProcessContext<C>;

    fn pre_exec(&mut self, mut context: C) -> Result<Self::Context, Error> {
        // we MUST box this to ensure that it stays in the same place
        let execution_data = Box::into_raw(Box::new(ExecutionContextData {
            executor: context
                .executor_mut()
                .take()
                .ok_or_else(|| Error::illegal_state("Missing executor for execution context"))?
                as *mut C::Executor as *mut c_void,
            fuzzer: context
                .fuzzer_mut()
                .take()
                .ok_or_else(|| Error::illegal_state("Missing fuzzer for execution context"))?
                as *mut C::Fuzzer as *mut c_void,
            state: context
                .state_mut()
                .take()
                .ok_or_else(|| Error::illegal_state("Missing state for execution context"))?
                as *mut C::State as *mut c_void,
            mgr: context.manager_mut().take().ok_or_else(|| {
                Error::illegal_state("Missing event manager for execution context")
            })? as *mut C::EventManager as *mut c_void,
            input: context
                .input_mut()
                .take()
                .ok_or_else(|| Error::illegal_state("Missing input for execution context"))?
                as *const C::Input as *const c_void,
        }));
        if CONTEXT.swap(execution_data, Ordering::Relaxed) != core::ptr::null_mut() {
            return Err(Error::illegal_state(
                "Attempted to replace execution context, but it was already full",
            ));
        }

        // install the handlers!
        H::install()?;

        Ok(InProcessContext::new(context))
    }

    fn post_exec(&mut self, context: Self::Context) -> Result<C, Error> {
        H::uninstall()?;

        let execution_data = CONTEXT.swap(core::ptr::null_mut(), Ordering::Relaxed);
        if execution_data == core::ptr::null_mut() {
            return Err(Error::illegal_state(
                "Attempted to clear execution context, but it was already cleared",
            ));
        }
        let mut context = context.context;
        unsafe {
            let execution_data = Box::from_raw(execution_data);
            context.executor_mut().replace(execution_data.executor());
            context.fuzzer_mut().replace(execution_data.fuzzer());
            context.state_mut().replace(execution_data.state());
            context.manager_mut().replace(execution_data.manager());
            context.input_mut().replace(execution_data.input());
        }

        Ok(context)
    }
}

// Definition with the execution context already installed for inserting multiple in-process hooks
impl<'a, H, C> ExecutorHook<InProcessContext<C>> for InProcessHook<H>
where
    H: InProcessHookHandler<C>,
    C: HookContext<'a> + 'a,
{
    type Context = InProcessContext<C>;

    fn pre_exec(&mut self, context: Self::Context) -> Result<Self::Context, Error> {
        // install the handlers!
        H::install()?;

        Ok(context)
    }

    fn post_exec(&mut self, context: Self::Context) -> Result<Self::Context, Error> {
        H::uninstall()?;

        Ok(context)
    }
}

/// Default callback for timeouts, regardless of platform
pub fn on_timeout(guard: &mut impl InProcessStateSaver) {
    log::error!("Timeout in fuzz run.");

    guard.run_observers_and_save_state(ExitKind::Timeout);

    log::info!("Exiting");

    unsafe {
        libc::_exit(55);
    }
}

/// [`InProcessHook`]s for handling Rust panics
#[cfg(feature = "std")]
pub mod panic {
    use alloc::boxed::Box;
    use std::{
        marker::PhantomData,
        panic,
        panic::PanicHookInfo,
        sync::atomic::{AtomicPtr, Ordering},
    };

    use libafl_bolts::Error;

    use crate::{
        executors::{
            hooks::inprocess::{
                GlobalContextGuard, InProcessHook, InProcessHookHandler, InProcessStateSaver,
            },
            ExitKind,
        },
        prelude::hooks::HookContext,
    };

    /// Callback for [`PanicHookHandler`] which will run when a Rust panic occurs
    pub trait PanicCallback<'a, C> {
        /// Handle the panic
        fn on_panic(info: &PanicHookInfo);
    }

    /// Default callback for [`PanicHookHandler`], which invokes [`run_observers_and_save_state`]
    /// and denotes that the [`ExitKind`] is [`ExitKind::Crash`].
    #[derive(Debug)]
    pub struct StdPanicCallback;

    impl<'a, C> PanicCallback<'a, C> for StdPanicCallback
    where
        C: HookContext<'a>,
        GlobalContextGuard<'a, C::Executor, C::EventManager, C::Input, C::State, C::Fuzzer>:
            InProcessStateSaver,
    {
        fn on_panic(_info: &PanicHookInfo) {
            let maybe_guard = unsafe { GlobalContextGuard::take_global::<C>() };
            if let Some(mut guard) = maybe_guard {
                guard.run_observers_and_save_state(ExitKind::Crash);

                unsafe {
                    libc::_exit(128 + 6); // SIGABRT exit code
                }
            } else {
            }
        }
    }

    /// Install a panic hook via [`panic::set_hook`]
    #[derive(Debug)]
    pub struct PanicHookHandler<A = StdPanicCallback>(PhantomData<fn() -> A>);

    struct OldHookHolder {
        hook: Box<dyn Fn(&PanicHookInfo<'_>) + 'static + Sync + Send>,
    }

    static OLD_HOOK: AtomicPtr<OldHookHolder> = AtomicPtr::new(core::ptr::null_mut());

    impl<A, C> InProcessHookHandler<C> for PanicHookHandler<A>
    where
        A: for<'a> PanicCallback<'a, C>,
    {
        fn install() -> Result<(), Error> {
            let hook = panic::take_hook();
            let holder = Box::leak(Box::new(OldHookHolder { hook }));
            OLD_HOOK.store(holder, Ordering::Relaxed);

            panic::set_hook(Box::new(move |panic_info| unsafe {
                if let Some(holder) = OLD_HOOK
                    .swap(core::ptr::null_mut(), Ordering::Relaxed)
                    .as_mut()
                {
                    (holder.hook)(panic_info);
                    A::on_panic(panic_info);
                }
            }));
            Ok(())
        }

        fn uninstall() -> Result<(), Error> {
            let holder = unsafe {
                OLD_HOOK
                    .swap(core::ptr::null_mut(), Ordering::Relaxed)
                    .as_mut()
                    .ok_or_else(|| {
                        Error::illegal_state("Old hook was unset, but we should have installed it")
                    })?
            };
            let holder = unsafe { Box::from_raw(holder) };
            panic::set_hook(holder.hook);
            Ok(())
        }
    }

    /// The [`InProcessHook`] which installs a handler for panics via [`panic::set_hook`]
    pub type InProcessPanicHook<A = StdPanicCallback> = InProcessHook<PanicHookHandler<A>>;
}
