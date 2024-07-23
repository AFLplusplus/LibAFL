//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
#[cfg(emulation_mode = "usermode")]
use core::ptr;
use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    time::Duration,
};

#[cfg(feature = "fork")]
use libafl::{
    events::EventManager, executors::InProcessForkExecutor, state::HasLastReportTime, HasMetadata,
};
use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{
        hooks::inprocess::InProcessExecutorHandlerData,
        inprocess::{HasInProcessHooks, InProcessExecutor},
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    observers::{ObserversTuple, UsesObservers},
    state::{HasCorpus, HasExecutions, HasSolutions, State, UsesState},
    Error, ExecutionProcessor, HasScheduler,
};
#[cfg(feature = "fork")]
use libafl_bolts::shmem::ShMemProvider;
use libafl_bolts::{
    os::unix_signals::{siginfo_t, ucontext_t, Signal},
    tuples::RefIndexable,
};

#[cfg(emulation_mode = "usermode")]
use crate::emu::EmulatorModules;
use crate::{command::CommandManager, modules::EmulatorModuleTuple, Emulator, EmulatorExitHandler};

/// A version of `QemuExecutor` with a state accessible from the harness.
pub mod stateful;

pub struct QemuExecutorState<'a, CM, EH, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    ET: EmulatorModuleTuple<S>,
    S: Unpin + State + HasExecutions,
{
    emulator: &'a mut Emulator<CM, EH, ET, S>,
}

pub struct QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
    S: Unpin + State + HasExecutions,
{
    inner: InProcessExecutor<'a, H, OT, S>,
    state: QemuExecutorState<'a, CM, EH, ET, S>,
}

impl<'a, CM, EH, H, OT, ET, S> Debug for QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S> + Debug,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasExecutions + Debug,
    OT: ObserversTuple<S> + Debug,
    ET: EmulatorModuleTuple<S> + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("emulator", &self.state.emulator)
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(emulation_mode = "usermode")]
extern "C" {
    // Original QEMU user signal handler
    fn libafl_qemu_handle_crash(signal: i32, info: *mut siginfo_t, puc: *mut c_void);
}

#[cfg(emulation_mode = "usermode")]
pub unsafe fn inproc_qemu_crash_handler<'a, E, EM, OF, Z, ET, S>(
    signal: Signal,
    info: &'a mut siginfo_t,
    mut context: Option<&'a mut ucontext_t>,
    _data: &'a mut InProcessExecutorHandlerData,
) where
    E: Executor<EM, Z> + HasObservers,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasExecutions + HasSolutions + HasCorpus,
    Z: HasObjective<Objective = OF, State = E::State>,
    ET: EmulatorModuleTuple<S> + Debug + 'a,
    S: Unpin + State + HasExecutions + 'a,
{
    let puc = match &mut context {
        Some(v) => ptr::from_mut::<ucontext_t>(*v) as *mut c_void,
        None => ptr::null_mut(),
    };
    libafl_qemu_handle_crash(signal as i32, info, puc);
}

#[cfg(emulation_mode = "systemmode")]
pub(crate) static mut BREAK_ON_TMOUT: bool = false;

#[cfg(emulation_mode = "systemmode")]
extern "C" {
    fn qemu_system_debug_request();
}

#[cfg(emulation_mode = "systemmode")]
pub unsafe fn inproc_qemu_timeout_handler<'a, E, EM, OF, Z>(
    signal: Signal,
    info: &'a mut siginfo_t,
    context: Option<&'a mut ucontext_t>,
    data: &'a mut InProcessExecutorHandlerData,
) where
    E: Executor<EM, Z> + HasObservers + HasInProcessHooks<E::State>,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasSolutions + HasCorpus + HasExecutions,
    Z: HasObjective<Objective = OF, State = E::State> + ExecutionProcessor + HasScheduler,
{
    if BREAK_ON_TMOUT {
        qemu_system_debug_request();
    } else {
        libafl::executors::hooks::unix::unix_signal_handler::inproc_timeout_handler::<E, EM, OF, Z>(
            signal, info, context, data,
        );
    }
}

impl<'a, CM, EH, ET, S> QemuExecutorState<'a, CM, EH, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    ET: EmulatorModuleTuple<S> + Debug,
    S: Unpin + State + HasExecutions + HasCorpus + HasSolutions,
{
    #[cfg(emulation_mode = "systemmode")]
    pub fn new<E, EM, OF, OT, Z>(emulator: &'a mut Emulator<CM, EH, ET, S>) -> Result<Self, Error>
    where
        E: Executor<EM, Z, State = S> + HasInProcessHooks<S> + HasObservers,
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        OT: ObserversTuple<S>,
        Z: HasObjective<Objective = OF, State = S>,
    {
        Ok(QemuExecutorState { emulator })
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn new<E, EM, OF, OT, Z>(emulator: &'a mut Emulator<CM, EH, ET, S>) -> Result<Self, Error>
    where
        E: Executor<EM, Z, State = S> + HasInProcessHooks<S> + HasObservers,
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        OT: ObserversTuple<S>,
        Z: HasObjective<Objective = OF, State = S> + ExecutionProcessor + HasScheduler,
    {
        #[cfg(emulation_mode = "usermode")]
        {
            let handler = |emulator_modules: &mut EmulatorModules<ET, S>, host_sig| {
                eprintln!("Crashed with signal {host_sig}");
                unsafe {
                    libafl::executors::inprocess::generic_inproc_crash_handler::<E, EM, OF, Z>();
                }
                if let Some(cpu) = emulator_modules.qemu().current_cpu() {
                    eprint!("Context:\n{}", cpu.display_context());
                }
            };

            emulator.modules_mut().crash_closure(Box::new(handler));
        }
        Ok(QemuExecutorState { emulator })
    }

    #[must_use]
    pub fn emulator(&self) -> &Emulator<CM, EH, ET, S> {
        self.emulator
    }

    pub fn emulator_mut(&mut self) -> &mut Emulator<CM, EH, ET, S> {
        self.emulator
    }
}

impl<'a, CM, EH, H, OT, ET, S> QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S> + Debug,
{
    pub fn new<EM, OF, Z>(
        emulator: &'a mut Emulator<CM, EH, ET, S>,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: Unpin + State + HasExecutions + HasCorpus + HasSolutions,
        Z: HasObjective<Objective = OF, State = S> + HasScheduler + ExecutionProcessor,
    {
        let mut inner = InProcessExecutor::with_timeout(
            harness_fn, observers, fuzzer, state, event_mgr, timeout,
        )?;

        #[cfg(emulation_mode = "usermode")]
        {
            inner.inprocess_hooks_mut().crash_handler =
                inproc_qemu_crash_handler::<InProcessExecutor<'a, H, OT, S>, EM, OF, Z, ET, S>
                    as *const c_void;
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            inner.inprocess_hooks_mut().timeout_handler =
                inproc_qemu_timeout_handler::<InProcessExecutor<'a, H, OT, S>, EM, OF, Z>
                    as *const c_void;
        }

        let state =
            QemuExecutorState::new::<InProcessExecutor<'a, H, OT, S>, EM, OF, OT, Z>(emulator)?;

        Ok(Self { inner, state })
    }

    pub fn inner(&self) -> &InProcessExecutor<'a, H, OT, S> {
        &self.inner
    }

    #[cfg(emulation_mode = "systemmode")]
    pub fn break_on_timeout(&mut self) {
        unsafe {
            BREAK_ON_TMOUT = true;
        }
    }

    pub fn inner_mut(&mut self) -> &mut InProcessExecutor<'a, H, OT, S> {
        &mut self.inner
    }
}

impl<'a, CM, EH, ET, S> QemuExecutorState<'a, CM, EH, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    ET: EmulatorModuleTuple<S>,
    S: Unpin + State + HasExecutions,
{
    fn pre_exec<E, EM, OF, Z>(&mut self, input: &E::Input)
    where
        E: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        Z: HasObjective<Objective = OF, State = S>,
    {
        self.emulator.first_exec_all();

        self.emulator.pre_exec_all(input);
    }

    fn post_exec<E, EM, OT, OF, Z>(
        &mut self,
        input: &E::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        E: Executor<EM, Z, State = S> + HasObservers,
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OT: ObserversTuple<S>,
        OF: Feedback<S>,
        Z: HasObjective<Objective = OF, State = S>,
    {
        self.emulator.post_exec_all(input, observers, exit_kind);
    }
}

impl<'a, CM, EH, EM, H, OT, OF, ET, S, Z> Executor<EM, Z> for QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasExecutions + HasCorpus + HasSolutions,
    OT: ObserversTuple<S>,
    OF: Feedback<S>,
    ET: EmulatorModuleTuple<S> + Debug,
    Z: HasObjective<Objective = OF, State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        self.state.pre_exec::<Self, EM, OF, Z>(input);
        let mut exit_kind = self.inner.run_target(fuzzer, state, mgr, input)?;
        self.state.post_exec::<Self, EM, OT, OF, Z>(
            input,
            &mut *self.inner.observers_mut(),
            &mut exit_kind,
        );
        Ok(exit_kind)
    }
}

impl<'a, CM, EH, H, OT, ET, S> UsesState for QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
    S: Unpin + State + HasExecutions,
{
    type State = S;
}

impl<'a, CM, EH, H, OT, ET, S> UsesObservers for QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
    S: Unpin + State + HasExecutions,
{
    type Observers = OT;
}

impl<'a, CM, EH, H, OT, ET, S> HasObservers for QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
{
    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        self.inner.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        self.inner.observers_mut()
    }
}

#[cfg(feature = "fork")]
pub struct QemuForkExecutor<'a, CM, EH, H, OT, ET, S, SP, EM, Z>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
    SP: ShMemProvider,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    inner: InProcessForkExecutor<'a, H, OT, S, SP, EM, Z>,
    state: QemuExecutorState<'a, CM, EH, ET, S>,
}

#[cfg(feature = "fork")]
impl<'a, CM, EH, H, OT, ET, S, SP, EM, Z> Debug
    for QemuForkExecutor<'a, CM, EH, H, OT, ET, S, SP, EM, Z>
where
    CM: CommandManager<EH, ET, S> + Debug,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasExecutions + Debug,
    OT: ObserversTuple<S> + Debug,
    ET: EmulatorModuleTuple<S> + Debug,
    SP: ShMemProvider,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuForkExecutor")
            .field("emulator", &self.state.emulator)
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(feature = "fork")]
impl<'a, CM, EH, H, OT, ET, S, SP, EM, Z, OF> QemuForkExecutor<'a, CM, EH, H, OT, ET, S, SP, EM, Z>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
    SP: ShMemProvider,
    EM: EventFirer<State = S> + EventRestarter,
    OF: Feedback<S>,
    S: Unpin + HasSolutions,
    Z: HasObjective<Objective = OF, State = S>,
{
    pub fn new(
        emulator: &'a mut Emulator<CM, EH, ET, S>,
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
            inner: InProcessForkExecutor::new(
                harness_fn,
                observers,
                fuzzer,
                state,
                event_mgr,
                timeout,
                shmem_provider,
            )?,
            state: QemuExecutorState { emulator },
        })
    }

    pub fn inner(&self) -> &InProcessForkExecutor<'a, H, OT, S, SP, EM, Z> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut InProcessForkExecutor<'a, H, OT, S, SP, EM, Z> {
        &mut self.inner
    }

    pub fn emulator(&self) -> &Emulator<CM, EH, ET, S> {
        self.state.emulator
    }
}

#[cfg(feature = "fork")]
impl<'a, CM, EH, EM, H, OT, ET, S, Z, SP, OF> Executor<EM, Z>
    for QemuForkExecutor<'a, CM, EH, H, OT, ET, S, SP, EM, Z>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    EM: EventManager<InProcessForkExecutor<'a, H, OT, S, SP, EM, Z>, Z, State = S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasMetadata + HasExecutions + HasLastReportTime + HasCorpus + HasSolutions,
    OT: ObserversTuple<S> + Debug,
    ET: EmulatorModuleTuple<S>,
    SP: ShMemProvider,
    OF: Feedback<S>,
    Z: HasObjective<Objective = OF, State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        self.inner.run_target(fuzzer, state, mgr, input)
    }
}

#[cfg(feature = "fork")]
impl<'a, CM, EH, H, OT, ET, S, SP, EM, Z> UsesObservers
    for QemuForkExecutor<'a, CM, EH, H, OT, ET, S, SP, EM, Z>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
    S: Unpin + State + HasExecutions,
    SP: ShMemProvider,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    type Observers = OT;
}

#[cfg(feature = "fork")]
impl<'a, CM, EH, H, OT, ET, S, SP, EM, Z> UsesState
    for QemuForkExecutor<'a, CM, EH, H, OT, ET, S, SP, EM, Z>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
    S: Unpin + State + HasExecutions,
    SP: ShMemProvider,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    type State = S;
}

#[cfg(feature = "fork")]
impl<'a, CM, EH, H, OT, ET, S, SP, EM, Z> HasObservers
    for QemuForkExecutor<'a, CM, EH, H, OT, ET, S, SP, EM, Z>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
    SP: ShMemProvider,
    EM: UsesState<State = S>,
    Z: UsesState<State = S>,
{
    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        self.inner.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        self.inner.observers_mut()
    }
}
