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
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::inprocess::InProcessExecutorHandlerData,
        inprocess::{stateful::StatefulInProcessExecutor, HasInProcessHooks},
        inprocess_fork::stateful::StatefulInProcessForkExecutor,
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::ObserversTuple,
    state::{HasCorpus, HasExecutions, HasSolutions, State, UsesState},
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
use crate::{command::CommandManager, modules::EmulatorModuleTuple, Emulator, EmulatorDriver};

pub struct QemuExecutor<'a, CM, ED, ET, H, OT, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &mut S, &S::Input) -> ExitKind,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    inner: StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, ED, ET, S, SM>>,
    first_exec: bool,
}

/// # Safety
///
/// This should be used as a crash handler, and nothing else.
#[cfg(feature = "usermode")]
unsafe fn inproc_qemu_crash_handler<ET, S>(
    signal: Signal,
    info: &mut siginfo_t,
    mut context: Option<&mut ucontext_t>,
    _data: &mut InProcessExecutorHandlerData,
) where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
    let puc = match &mut context {
        Some(v) => ptr::from_mut::<ucontext_t>(*v) as *mut c_void,
        None => ptr::null_mut(),
    };

    // run modules' crash callback
    if let Some(emulator_modules) = EmulatorModules::<ET, S>::emulator_modules_mut() {
        emulator_modules.modules_mut().on_crash_all();
    }

    libafl_qemu_handle_crash(signal as i32, info, puc);
}

#[cfg(feature = "systemmode")]
pub(crate) static BREAK_ON_TMOUT: AtomicBool = AtomicBool::new(false);

/// # Safety
/// Can call through the `unix_signal_handler::inproc_timeout_handler`.
/// Calling this method multiple times concurrently can lead to race conditions.
pub unsafe fn inproc_qemu_timeout_handler<E, EM, ET, OF, S, Z>(
    signal: Signal,
    info: &mut siginfo_t,
    context: Option<&mut ucontext_t>,
    data: &mut InProcessExecutorHandlerData,
) where
    E: HasObservers + HasInProcessHooks<E::State> + Executor<EM, Z>,
    E::Observers: ObserversTuple<E::Input, E::State>,
    E::State: HasExecutions + HasSolutions + HasCorpus,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    ET: EmulatorModuleTuple<S>,
    OF: Feedback<EM, E::Input, E::Observers, E::State>,
    S: State + Unpin,
    Z: HasObjective<Objective = OF, State = E::State>,
    <<E as UsesState>::State as HasSolutions>::Solutions: Corpus<Input = E::Input>, //delete me
    <<<E as UsesState>::State as HasCorpus>::Corpus as Corpus>::Input: Clone,       //delete me
{
    #[cfg(feature = "systemmode")]
    {
        if BREAK_ON_TMOUT.load(Ordering::Acquire) {
            libafl_exit_request_timeout();
        } else {
            libafl::executors::hooks::unix::unix_signal_handler::inproc_timeout_handler::<
                E,
                EM,
                OF,
                Z,
            >(signal, info, context, data);
        }
    }

    #[cfg(feature = "usermode")]
    {
        // run modules' crash callback
        if let Some(emulator_modules) = EmulatorModules::<ET, S>::emulator_modules_mut() {
            emulator_modules.modules_mut().on_timeout_all();
        }

        libafl::executors::hooks::unix::unix_signal_handler::inproc_timeout_handler::<E, EM, OF, Z>(
            signal, info, context, data,
        );
    }
}

impl<CM, ED, ET, H, OT, S, SM> Debug for QemuExecutor<'_, CM, ED, ET, H, OT, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    ET: EmulatorModuleTuple<S> + Debug,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &mut S, &S::Input) -> ExitKind,
    OT: ObserversTuple<S::Input, S> + Debug,
    S: State,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, CM, ED, ET, H, OT, S, SM> QemuExecutor<'a, CM, ED, ET, H, OT, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &mut S, &S::Input) -> ExitKind,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    pub fn new<EM, OF, Z>(
        emulator: Emulator<CM, ED, ET, S, SM>,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        ED: EmulatorDriver<CM, ET, S, SM>,
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<EM, S::Input, OT, S>,
        S: Unpin + State + HasExecutions + HasCorpus + HasSolutions,
        Z: HasObjective<Objective = OF, State = S>
            + HasScheduler<State = S>
            + ExecutionProcessor<EM, OT>,
        S::Solutions: Corpus<Input = S::Input>, //delete me
        <S::Corpus as Corpus>::Input: Clone,    //delete me
    {
        let mut inner = StatefulInProcessExecutor::with_timeout(
            harness_fn, emulator, observers, fuzzer, state, event_mgr, timeout,
        )?;

        #[cfg(feature = "usermode")]
        {
            inner.inprocess_hooks_mut().crash_handler =
                inproc_qemu_crash_handler::<ET, S> as *const c_void;

            let handler = |emulator_modules: &mut EmulatorModules<ET, S>, host_sig| {
                eprintln!("Crashed with signal {host_sig}");
                unsafe {
                    libafl::executors::inprocess::generic_inproc_crash_handler::<Self, EM, OF, Z>();
                }
                if let Some(cpu) = emulator_modules.qemu().current_cpu() {
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
            StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, ED, ET, S, SM>>,
            EM,
            ET,
            OF,
            S,
            Z,
        > as *const c_void;

        Ok(Self {
            inner,
            first_exec: true,
        })
    }

    pub fn inner(&self) -> &StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, ED, ET, S, SM>> {
        &self.inner
    }

    #[cfg(feature = "systemmode")]
    pub fn break_on_timeout(&mut self) {
        BREAK_ON_TMOUT.store(true, Ordering::Release);
    }

    pub fn inner_mut(
        &mut self,
    ) -> &mut StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, ED, ET, S, SM>> {
        &mut self.inner
    }
}

impl<CM, ED, EM, ET, H, OT, S, SM, Z> Executor<EM, Z> for QemuExecutor<'_, CM, ED, ET, H, OT, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    ED: EmulatorDriver<CM, ET, S, SM>,
    EM: UsesState<State = S>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &mut S, &S::Input) -> ExitKind,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasExecutions + Unpin,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
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

impl<CM, ED, ET, H, OT, S, SM> UsesState for QemuExecutor<'_, CM, ED, ET, H, OT, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &mut S, &S::Input) -> ExitKind,
    OT: ObserversTuple<S::Input, S>,
    S: State,
{
    type State = S;
}

impl<CM, ED, ET, H, OT, S, SM> HasObservers for QemuExecutor<'_, CM, ED, ET, H, OT, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &mut S, &S::Input) -> ExitKind,
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

pub type QemuInProcessForkExecutor<'a, CM, ED, EM, ET, H, OT, S, SM, SP, Z> =
    StatefulInProcessForkExecutor<'a, H, OT, S, SP, Emulator<CM, ED, ET, S, SM>, EM, Z>;

#[cfg(feature = "fork")]
pub struct QemuForkExecutor<'a, CM, ED, EM, ET, H, OT, S, SM, SP, Z>
where
    CM: CommandManager<ED, ET, S, SM>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: UsesInput,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
{
    inner: QemuInProcessForkExecutor<'a, CM, ED, EM, ET, H, OT, S, SM, SP, Z>,
}

#[cfg(feature = "fork")]
impl<CM, ED, EM, ET, H, OT, S, SM, SP, Z> Debug
    for QemuForkExecutor<'_, CM, ED, EM, ET, H, OT, S, SM, SP, Z>
where
    CM: CommandManager<ED, ET, S, SM> + Debug,
    EM: UsesState<State = S>,
    ED: Debug,
    ET: EmulatorModuleTuple<S> + Debug,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S> + Debug,
    S: UsesInput + Debug,
    SM: Debug,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuForkExecutor")
            .field("inner", &self.inner)
            .field("emulator", &self.inner.exposed_executor_state)
            .finish()
    }
}

#[cfg(feature = "fork")]
impl<'a, CM, ED, EM, ET, H, OT, S, SM, SP, Z>
    QemuForkExecutor<'a, CM, ED, EM, ET, H, OT, S, SM, SP, Z>
where
    CM: CommandManager<ED, ET, S, SM>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: State + HasSolutions,
    SP: ShMemProvider,
    Z: HasObjective<State = S>,
    Z::Objective: Feedback<EM, S::Input, OT, S>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        emulator: Emulator<CM, ED, ET, S, SM>,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
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
                fuzzer,
                state,
                event_mgr,
                timeout,
                shmem_provider,
            )?,
        })
    }

    pub fn inner(&self) -> &QemuInProcessForkExecutor<'a, CM, ED, EM, ET, H, OT, S, SM, SP, Z> {
        &self.inner
    }

    pub fn inner_mut(
        &mut self,
    ) -> &mut QemuInProcessForkExecutor<'a, CM, ED, EM, ET, H, OT, S, SM, SP, Z> {
        &mut self.inner
    }

    pub fn emulator(&self) -> &Emulator<CM, ED, ET, S, SM> {
        &self.inner.exposed_executor_state
    }

    pub fn emulator_mut(&mut self) -> &Emulator<CM, ED, ET, S, SM> {
        &mut self.inner.exposed_executor_state
    }
}

#[cfg(feature = "fork")]
impl<CM, ED, EM, ET, H, OF, OT, S, SM, SP, Z> Executor<EM, Z>
    for QemuForkExecutor<'_, CM, ED, EM, ET, H, OT, S, SM, SP, Z>
where
    CM: CommandManager<ED, ET, S, SM>,
    ED: EmulatorDriver<CM, ET, S, SM>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &S::Input) -> ExitKind,
    OF: Feedback<EM, S::Input, OT, S>,
    OT: ObserversTuple<S::Input, S> + Debug,
    S: State + HasExecutions + Unpin,
    SP: ShMemProvider,
    Z: HasObjective<Objective = OF, State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
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
impl<CM, ED, EM, ET, H, OT, S, SM, SP, Z> UsesState
    for QemuForkExecutor<'_, CM, ED, EM, ET, H, OT, S, SM, SP, Z>
where
    CM: CommandManager<ED, ET, S, SM>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: State,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
{
    type State = S;
}

#[cfg(feature = "fork")]
impl<CM, ED, EM, ET, H, OT, S, SM, SP, Z> HasObservers
    for QemuForkExecutor<'_, CM, ED, EM, ET, H, OT, S, SM, SP, Z>
where
    CM: CommandManager<ED, ET, S, SM>,
    EM: UsesState<State = S>,
    ET: EmulatorModuleTuple<S>,
    H: FnMut(&mut Emulator<CM, ED, ET, S, SM>, &S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S::Input, S>,
    S: State,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
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
