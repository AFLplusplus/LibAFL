//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    time::Duration,
};
#[cfg(feature = "systemmode")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "usermode")]
use std::{ptr, str};

#[cfg(feature = "usermode")]
use libafl::state::HasCorpus;
use libafl::{
    Error, ExecutionProcessor,
    events::{EventFirer, EventRestarter},
    executors::{
        Executor, ExitKind, HasObservers,
        hooks::inprocess::InProcessExecutorHandlerData,
        inprocess::{HasInProcessHooks, stateful::StatefulInProcessExecutor},
        inprocess_fork::stateful::StatefulInProcessForkExecutor,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasCurrentTestcase, HasExecutions, HasSolutions},
};
#[cfg(feature = "usermode")]
use libafl_bolts::minibsod;
#[cfg(feature = "fork")]
use libafl_bolts::shmem::ShMemProvider;
use libafl_bolts::{
    os::unix_signals::{Signal, ucontext_t},
    tuples::RefIndexable,
};
#[cfg(feature = "systemmode")]
use libafl_qemu_sys::libafl_exit_request_timeout;
use libc::siginfo_t;

use crate::{Emulator, EmulatorDriver, command::CommandManager, modules::EmulatorModuleTuple};
#[cfg(feature = "usermode")]
use crate::{EmulatorModules, Qemu, QemuSignalContext, run_target_crash_hooks};

type EmulatorInProcessExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, Z> =
    StatefulInProcessExecutor<'a, EM, Emulator<C, CM, ED, ET, I, S, SM>, H, I, OT, S, Z>;

#[cfg(feature = "systemmode")]
pub(crate) static BREAK_ON_TMOUT: AtomicBool = AtomicBool::new(false);

pub struct QemuExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, Z> {
    inner: EmulatorInProcessExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, Z>,
    first_exec: bool,
}

/// `LibAFL` QEMU main crash handler.
/// Be careful, it can come after QEMU's native crash handler if a signal is caught by QEMU but
/// not by `LibAFL`.
///
/// Signals handlers can be nested.
///
/// # Safety
///
/// This should be used as a crash handler, and nothing else.
#[cfg(feature = "usermode")]
pub unsafe fn inproc_qemu_crash_handler<E, EM, ET, I, OF, S, Z>(
    signal: Signal,
    info: &mut siginfo_t,
    mut context: Option<&mut ucontext_t>,
    data: &mut InProcessExecutorHandlerData,
) where
    ET: EmulatorModuleTuple<I, S>,
    E: Executor<EM, I, S, Z> + HasObservers,
    E::Observers: ObserversTuple<I, S>,
    EM: EventFirer<I, S> + EventRestarter<S>,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasExecutions + HasSolutions<I> + HasCorpus<I> + HasCurrentTestcase<I> + Unpin,
    Z: HasObjective<Objective = OF>,
    I: Input + Clone + Unpin,
{
    log::debug!("QEMU signal handler has been triggered (signal {signal})");

    let puc = match &mut context {
        Some(v) => ptr::from_mut::<ucontext_t>(*v) as *mut c_void,
        None => ptr::null_mut(),
    };

    if let Some(qemu) = Qemu::get() {
        // QEMU is already initialized, we have to route the signal to QEMU's handler or
        // consider it as a host (i.e. fuzzer) signal

        if qemu.is_running() {
            // QEMU is running, we must determine if we are coming from qemu's signal handler or not
            log::debug!("Signal has been triggered while QEMU was running");

            match qemu.signal_ctx() {
                QemuSignalContext::OutOfQemuSignalHandler => {
                    // we did not run QEMU's signal handler, run it not
                    log::debug!("It's a simple signal, let QEMU handle it first");

                    unsafe {
                        qemu.run_signal_handler(signal.into(), info, puc);
                    }

                    // if we are there, we can safely resume from the signal handler.
                    return;
                }
                QemuSignalContext::InQemuSignalHandlerHost => {
                    // we are running in a nested signal handling
                    // and the signal is a host QEMU signal

                    let si_addr = unsafe { info.si_addr() as usize };
                    log::error!(
                        "QEMU Host crash crashed at addr 0x{si_addr:x}... Bug in QEMU or Emulator modules? Exiting.\n"
                    );

                    if let Some(cpu) = qemu.current_cpu() {
                        eprint!("QEMU Context:\n{}", cpu.display_context());
                    }
                }
                QemuSignalContext::InQemuSignalHandlerTarget => {
                    // we are running in a nested signal handler and the signal is a target signal.
                    // run qemu hooks then report the crash.

                    log::debug!(
                        "QEMU Target signal received that should be handled by host. It is a target crash."
                    );

                    log::debug!("Running crash hooks.");
                    run_target_crash_hooks::<ET, I, S>(signal.into());

                    assert!(unsafe { data.maybe_report_crash::<E, EM, I, OF, S, Z>(None) });

                    if let Some(cpu) = qemu.current_cpu() {
                        eprint!("QEMU Context:\n{}", cpu.display_context());
                    }
                }
            }
        } else {
            // qemu is not running, it is a bug in LibAFL
            let si_addr = unsafe { info.si_addr() as usize };
            log::error!("The fuzzer crashed at addr 0x{si_addr:x}... Bug in the fuzzer? Exiting.");

            let bsod = minibsod::generate_minibsod_to_vec(signal, info, context.as_deref());

            if let Ok(bsod) = bsod {
                if let Ok(bsod_str) = str::from_utf8(&bsod) {
                    log::error!("\n{bsod_str}");
                } else {
                    log::error!("convert minibsod to string failed");
                }
            } else {
                log::error!("generate_minibsod failed");
            }
        }
    }

    unsafe {
        libc::_exit(128 + (signal as i32));
    }
}

/// # Safety
/// Can call through the `unix_signal_handler::inproc_timeout_handler`.
/// Calling this method multiple times concurrently can lead to race conditions.
pub unsafe fn inproc_qemu_timeout_handler<E, EM, ET, I, OF, S, Z>(
    signal: Signal,
    info: &mut siginfo_t,
    context: Option<&mut ucontext_t>,
    data: &mut InProcessExecutorHandlerData,
) where
    E: HasObservers + HasInProcessHooks<I, S>,
    E::Observers: ObserversTuple<I, S>,
    EM: EventFirer<I, S> + EventRestarter<S>,
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    OF: Feedback<EM, I, E::Observers, S>,
    S: HasExecutions + HasSolutions<I> + Unpin + HasCurrentTestcase<I>,
    I: Input,
    Z: HasObjective<Objective = OF>,
{
    #[cfg(feature = "systemmode")]
    unsafe {
        if BREAK_ON_TMOUT.load(Ordering::Acquire) {
            libafl_exit_request_timeout();
        } else {
            libafl::executors::hooks::unix::unix_signal_handler::inproc_timeout_handler::<
                E,
                EM,
                I,
                OF,
                S,
                Z,
            >(signal, info, context, data);
        }
    }

    #[cfg(feature = "usermode")]
    unsafe {
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
            Z,
        >(signal, info, context, data);
    }
}

impl<C, CM, ED, EM, ET, H, I, OT, S, SM, Z> Debug
    for QemuExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, Z>
where
    OT: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, Z>
    QemuExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, Z>
where
    ET: EmulatorModuleTuple<I, S>,
    H: FnMut(&mut Emulator<C, CM, ED, ET, I, S, SM>, &mut S, &I) -> ExitKind,
    I: Input + Unpin,
    OT: ObserversTuple<I, S>,
    S: Unpin + HasExecutions + HasSolutions<I> + HasCurrentTestcase<I>,
{
    pub fn new<OF>(
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
        Z: HasObjective<Objective = OF> + ExecutionProcessor<EM, I, OT, S>,
    {
        let mut inner = StatefulInProcessExecutor::with_timeout(
            harness_fn, emulator, observers, fuzzer, state, event_mgr, timeout,
        )?;

        // rewrite the crash handler pointer
        #[cfg(feature = "usermode")]
        {
            inner.inprocess_hooks_mut().crash_handler =
                inproc_qemu_crash_handler::<Self, EM, ET, I, OF, S, Z> as *const c_void;
        }

        // rewrite the timeout handler pointer
        inner.inprocess_hooks_mut().timeout_handler = inproc_qemu_timeout_handler::<
            StatefulInProcessExecutor<'a, EM, Emulator<C, CM, ED, ET, I, S, SM>, H, I, OT, S, Z>,
            EM,
            ET,
            I,
            OF,
            S,
            Z,
        > as *const c_void;

        Ok(Self {
            inner,
            first_exec: true,
        })
    }

    pub fn inner(&self) -> &EmulatorInProcessExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, Z> {
        &self.inner
    }

    #[cfg(feature = "systemmode")]
    pub fn break_on_timeout(&mut self) {
        BREAK_ON_TMOUT.store(true, Ordering::Release);
    }

    pub fn inner_mut(
        &mut self,
    ) -> &mut EmulatorInProcessExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, Z> {
        &mut self.inner
    }
}

impl<C, CM, ED, EM, ET, H, I, OT, S, SM, Z> Executor<EM, I, S, Z>
    for QemuExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, Z>
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
        fuzzer: &mut Z,
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

        let mut exit_kind = self.inner.run_target(fuzzer, state, mgr, input)?;

        self.inner.exposed_executor_state.post_exec(
            input,
            &mut *self.inner.inner.observers_mut(),
            state,
            &mut exit_kind,
        );

        Ok(exit_kind)
    }
}

impl<C, CM, ED, EM, ET, H, I, OT, S, SM, Z> HasObservers
    for QemuExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, Z>
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

pub type QemuInProcessForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z> =
    StatefulInProcessForkExecutor<'a, EM, Emulator<C, CM, ED, ET, I, S, SM>, H, I, OT, S, SP, Z>;

#[cfg(feature = "fork")]
pub struct QemuForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z> {
    inner: QemuInProcessForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z>,
}

#[cfg(feature = "fork")]
impl<C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z> Debug
    for QemuForkExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z>
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
impl<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z>
    QemuForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z>
where
    EM: EventFirer<I, S> + EventRestarter<S>,
    ET: EmulatorModuleTuple<I, S>,
    OT: ObserversTuple<I, S>,
    S: HasSolutions<I>,
    SP: ShMemProvider,
    Z: HasObjective,
    Z::Objective: Feedback<EM, I, OT, S>,
{
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        emulator: Emulator<C, CM, ED, ET, I, S, SM>,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        shmem_provider: SP,
        timeout: Duration,
    ) -> Result<Self, Error> {
        assert!(
            !ET::HOOKS_DO_SIDE_EFFECTS,
            "When using QemuForkExecutor, the hooks must not do any side effect as they will happen in the child process and then discarded"
        );

        Ok(Self {
            inner: StatefulInProcessForkExecutor::new(
                harness_fn,
                emulator,
                observers,
                fuzzer,
                state,
                event_mgr,
                timeout,
                shmem_provider,
            )?,
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn inner(
        &self,
    ) -> &QemuInProcessForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z> {
        &self.inner
    }

    #[allow(clippy::type_complexity)]
    pub fn inner_mut(
        &mut self,
    ) -> &mut QemuInProcessForkExecutor<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z> {
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
impl<C, CM, ED, EM, ET, H, I, OF, OT, S, SM, SP, Z> Executor<EM, I, S, Z>
    for QemuForkExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z>
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
    Z: HasObjective<Objective = OF>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.inner.exposed_executor_state.first_exec(state);

        self.inner.exposed_executor_state.pre_exec(state, input);

        let mut exit_kind = self.inner.run_target(fuzzer, state, mgr, input)?;

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
impl<C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z> HasObservers
    for QemuForkExecutor<'_, C, CM, ED, EM, ET, H, I, OT, S, SM, SP, Z>
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
