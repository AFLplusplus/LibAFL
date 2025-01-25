//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    time::Duration,
};
#[cfg(feature = "usermode")]
use std::ptr;
#[cfg(feature = "systemmode")]
use std::sync::atomic::{AtomicBool, Ordering};

use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::inprocess::InProcessExecutorHandlerData,
        inprocess::{stateful::StatefulInProcessExecutor, HasInProcessHooks},
        inprocess_fork::stateful::StatefulInProcessForkExecutor,
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasCurrentTestcase, HasExecutions, HasSolutions},
    Error, ExecutionProcessor, HasScheduler,
};
#[cfg(feature = "fork")]
use libafl_bolts::shmem::ShMemProvider;
use libafl_bolts::{
    os::unix_signals::{ucontext_t, Signal},
    tuples::RefIndexable,
};
#[cfg(feature = "systemmode")]
use libafl_qemu_sys::libafl_exit_request_timeout;
#[cfg(feature = "usermode")]
use libafl_qemu_sys::libafl_qemu_handle_crash;
use libc::siginfo_t;

#[cfg(feature = "usermode")]
use crate::EmulatorModules;
#[cfg(feature = "usermode")]
use crate::Qemu;
use crate::{command::CommandManager, modules::EmulatorModuleTuple, Emulator, EmulatorDriver};

type EmulatorInProcessExecutor<'a, C, CM, ED, ET, H, I, OT, S, SM> =
    StatefulInProcessExecutor<'a, Emulator<C, CM, ED, ET, I, S, SM>, H, I, OT, S>;

pub struct QemuExecutor<'a, C, CM, ED, ET, H, I, OT, S, SM> {
    inner: EmulatorInProcessExecutor<'a, C, CM, ED, ET, H, I, OT, S, SM>,
    first_exec: bool,
}

/// # Safety
///
/// This should be used as a crash handler, and nothing else.
#[cfg(feature = "usermode")]
unsafe fn inproc_qemu_crash_handler<ET, I, S>(
    signal: Signal,
    info: &mut siginfo_t,
    mut context: Option<&mut ucontext_t>,
    _data: &mut InProcessExecutorHandlerData,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let puc = match &mut context {
        Some(v) => ptr::from_mut::<ucontext_t>(*v) as *mut c_void,
        None => ptr::null_mut(),
    };

    // run modules' crash callback
    if let Some(emulator_modules) = EmulatorModules::<ET, I, S>::emulator_modules_mut() {
        emulator_modules.modules_mut().on_crash_all();
    }

    libafl_qemu_handle_crash(signal as i32, info, puc);
}

#[cfg(feature = "systemmode")]
pub(crate) static BREAK_ON_TMOUT: AtomicBool = AtomicBool::new(false);

/// # Safety
/// Can call through the `unix_signal_handler::inproc_timeout_handler`.
/// Calling this method multiple times concurrently can lead to race conditions.
pub unsafe fn inproc_qemu_timeout_handler<E, EM, ET, I, OF, S>(
    signal: Signal,
    info: &mut siginfo_t,
    context: Option<&mut ucontext_t>,
    data: &mut InProcessExecutorHandlerData,
) where
    E: HasObservers + HasInProcessHooks<I, S> + Executor<EM, I, OF, S>,
    E::Observers: ObserversTuple<I, S>,
    EM: EventFirer<I, S> + EventRestarter<S>,
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasExecutions + HasSolutions<I> + Unpin + HasCurrentTestcase<I>,
    I: Input,
{
    #[cfg(feature = "systemmode")]
    {
        if BREAK_ON_TMOUT.load(Ordering::Acquire) {
            libafl_exit_request_timeout();
        } else {
            libafl::executors::hooks::unix::unix_signal_handler::inproc_timeout_handler::<
                E,
                EM,
                I,
                OF,
                S,
            >(signal, info, context, data);
        }
    }

    #[cfg(feature = "usermode")]
    {
        // run modules' crash callback
        if let Some(emulator_modules) = EmulatorModules::<ET, I, S>::emulator_modules_mut() {
            emulator_modules.modules_mut().on_timeout_all();
        }

        libafl::executors::hooks::unix::unix_signal_handler::inproc_timeout_handler::<
            E,
            EM,
            I,
            OF,
            S,
        >(signal, info, context, data);
    }
}

impl<C, CM, ED, ET, H, I, OT, S, SM> Debug for QemuExecutor<'_, C, CM, ED, ET, H, I, OT, S, SM>
where
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C, CM, ED, ET, H, I, OT, S, SM> QemuExecutor<'a, C, CM, ED, ET, H, I, OT, S, SM>
where
    ET: EmulatorModuleTuple<I, S>,
    H: FnMut(&mut Emulator<C, CM, ED, ET, I, S, SM>, &mut S, &I) -> ExitKind,
    I: Input + Unpin,
    OT: ObserversTuple<I, S>,
    S: Unpin + HasExecutions + HasSolutions<I> + HasCurrentTestcase<I>,
{
    pub fn new<EM, OF, Z>(
        emulator: Emulator<C, CM, ED, ET, I, S, SM>,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        C: Clone,
        CM: CommandManager<C, ED, ET, I, S, SM, Commands = C>,
        ED: EmulatorDriver<C, CM, ET, I, S, SM>,
        EM: EventFirer<I, S> + EventRestarter<S>,
        OF: Feedback<EM, I, OT, S>,
        Z: HasObjective<Objective = OF> + HasScheduler<I, S> + ExecutionProcessor<EM, I, OT, S>,
    {
        let mut inner = StatefulInProcessExecutor::with_timeout(
            harness_fn,
            emulator,
            observers,
            fuzzer.objective_mut(),
            state,
            event_mgr,
            timeout,
        )?;

        #[cfg(feature = "usermode")]
        {
            inner.inprocess_hooks_mut().crash_handler =
                inproc_qemu_crash_handler::<ET, I, S> as *const c_void;

            let handler = |qemu: Qemu,
                           _emulator_modules: &mut EmulatorModules<ET, I, S>,
                           host_sig| {
                eprintln!("Crashed with signal {host_sig}");
                unsafe {
                    libafl::executors::inprocess::generic_inproc_crash_handler::<Self, EM, I, OF, S>(
                    );
                }
                if let Some(cpu) = qemu.current_cpu() {
                    eprint!("Context:\n{}", cpu.display_context());
                }
            };

            // # Safety
            // We assume our crash handlers to be safe/quit after execution.
            unsafe {
                inner
                    .exposed_executor_state_mut()
                    .modules_mut()
                    .crash_closure(Box::new(handler));
            }
        }

        inner.inprocess_hooks_mut().timeout_handler = inproc_qemu_timeout_handler::<
            StatefulInProcessExecutor<'a, Emulator<C, CM, ED, ET, I, S, SM>, H, I, OT, S>,
            EM,
            ET,
            I,
            OF,
            S,
        > as *const c_void;

        Ok(Self {
            inner,
            first_exec: true,
        })
    }

    pub fn inner(&self) -> &EmulatorInProcessExecutor<'a, C, CM, ED, ET, H, I, OT, S, SM> {
        &self.inner
    }

    #[cfg(feature = "systemmode")]
    pub fn break_on_timeout(&mut self) {
        BREAK_ON_TMOUT.store(true, Ordering::Release);
    }

    pub fn inner_mut(
        &mut self,
    ) -> &mut EmulatorInProcessExecutor<'a, C, CM, ED, ET, H, I, OT, S, SM> {
        &mut self.inner
    }
}

impl<C, CM, ED, EM, ET, H, I, OF, OT, S, SM> Executor<EM, I, S>
    for QemuExecutor<'_, C, CM, ED, ET, H, I, OT, S, SM>
where
    C: Clone,
    CM: CommandManager<C, ED, ET, I, S, SM, Commands = C>,
    ED: EmulatorDriver<C, CM, ET, I, S, SM>,
    ET: EmulatorModuleTuple<I, S>,
    H: FnMut(&mut Emulator<C, CM, ED, ET, I, S, SM>, &mut S, &I) -> ExitKind,
    I: Unpin,
    OT: ObserversTuple<I, S>,
    S: HasExecutions + Unpin,
{
    fn run_target(
        &mut self,
        objective: &mut OF,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        if self.first_exec {
            self.inner.exposed_executor_state_mut().first_exec(state);
            self.first_exec = false;
        }

        self.inner
            .exposed_executor_state_mut()
            .pre_exec(state, input);

        let mut exit_kind = self.inner.run_target(objective, state, mgr, input)?;

        self.inner.exposed_executor_state.post_exec(
            input,
            &mut *self.inner.inner.observers_mut(),
            state,
            &mut exit_kind,
        );

        Ok(exit_kind)
    }
}

impl<C, CM, ED, ET, H, I, OT, S, SM> HasObservers
    for QemuExecutor<'_, C, CM, ED, ET, H, I, OT, S, SM>
where
    ET: EmulatorModuleTuple<I, S>,
    H: FnMut(&mut Emulator<C, CM, ED, ET, I, S, SM>, &mut S, &I) -> ExitKind,
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

pub type QemuInProcessForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP> =
    StatefulInProcessForkExecutor<'a, EM, Emulator<C, CM, ED, ET, I, S, SM>, H, I, OT, S, SP>;

#[cfg(feature = "fork")]
pub struct QemuForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP> {
    inner: QemuInProcessForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP>,
}

#[cfg(feature = "fork")]
impl<C, CM, ED, EM, ET, H, I, OT, S, SM, SP> Debug
    for QemuForkExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, SP>
where
    C: Debug,
    CM: Debug,
    ED: Debug,
    EM: Debug,
    ET: EmulatorModuleTuple<I, S> + Debug,
    OT: ObserversTuple<I, S> + Debug,
    I: Debug,
    S: Debug,
    SM: Debug,
    SP: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuForkExecutor")
            .field("inner", &self.inner)
            .field("emulator", &self.inner.exposed_executor_state)
            .finish()
    }
}

#[cfg(feature = "fork")]
impl<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP>
    QemuForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP>
where
    EM: EventFirer<I, S> + EventRestarter<S>,
    ET: EmulatorModuleTuple<I, S>,
    OT: ObserversTuple<I, S>,
    S: HasSolutions<I>,
    SP: ShMemProvider,
{
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        emulator: Emulator<C, CM, ED, ET, I, S, SM>,
        harness_fn: &'a mut H,
        observers: OT,
        objective: &mut OF,
        state: &mut S,
        event_mgr: &mut EM,
        shmem_provider: SP,
        timeout: Duration,
    ) -> Result<Self, Error> {
        assert!(!ET::HOOKS_DO_SIDE_EFFECTS, "When using QemuForkExecutor, the hooks must not do any side effect as they will happen in the child process and then discarded");

        Ok(Self {
            inner: StatefulInProcessForkExecutor::new(
                harness_fn,
                emulator,
                observers,
                objective,
                state,
                event_mgr,
                timeout,
                shmem_provider,
            )?,
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn inner(&self) -> &QemuInProcessForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP> {
        &self.inner
    }

    #[allow(clippy::type_complexity)]
    pub fn inner_mut(
        &mut self,
    ) -> &mut QemuInProcessForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP> {
        &mut self.inner
    }

    pub fn emulator(&self) -> &Emulator<C, CM, ED, ET, I, S, SM> {
        &self.inner.exposed_executor_state
    }

    pub fn emulator_mut(&mut self) -> &Emulator<C, CM, ED, ET, I, S, SM> {
        &mut self.inner.exposed_executor_state
    }
}

#[cfg(feature = "fork")]
impl<C, CM, ED, EM, ET, H, I, OF, OT, S, SM, SP> Executor<EM, I, OF, S>
    for QemuForkExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, SP>
where
    C: Clone,
    CM: CommandManager<C, ED, ET, I, S, SM, Commands = C>,
    ED: EmulatorDriver<C, CM, ET, I, S, SM>,
    EM: EventFirer<I, S> + EventRestarter<S>,
    ET: EmulatorModuleTuple<I, S>,
    H: FnMut(&mut Emulator<C, CM, ED, ET, I, S, SM>, &I) -> ExitKind,
    OF: Feedback<EM, I, OT, S>,
    OT: ObserversTuple<I, S> + Debug,
    I: Input + Unpin,
    S: HasExecutions + Unpin,
    SP: ShMemProvider,
{
    fn run_target(
        &mut self,
        objective: &mut OF,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.inner.exposed_executor_state.first_exec(state);

        self.inner.exposed_executor_state.pre_exec(state, input);

        let mut exit_kind = self.inner.run_target(objective, state, mgr, input)?;

        self.inner.exposed_executor_state.post_exec(
            input,
            &mut *self.inner.inner.observers_mut(),
            state,
            &mut exit_kind,
        );

        Ok(exit_kind)
    }
}

#[cfg(feature = "fork")]
impl<C, CM, ED, EM, ET, H, I, OT, S, SM, SP> HasObservers
    for QemuForkExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, SP>
where
    ET: EmulatorModuleTuple<I, S>,
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
