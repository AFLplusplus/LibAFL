//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    time::Duration,
};

#[cfg(emulation_mode = "usermode")]
use std::ptr;

use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{
        inprocess::{stateful::StatefulInProcessExecutor, HasInProcessHooks},
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    observers::{ObserversTuple, UsesObservers},
    state::{HasCorpus, HasExecutions, HasSolutions, State, UsesState},
    Error, ExecutionProcessor, HasScheduler,
};
use libafl::executors::hooks::inprocess::InProcessExecutorHandlerData;
use libafl_bolts::tuples::RefIndexable;
use crate::{command::CommandManager, modules::EmulatorModuleTuple, Emulator, EmulatorExitHandler};

#[cfg(feature = "fork")]
use libafl::{
    events::EventManager, executors::InProcessForkExecutor, state::HasLastReportTime, HasMetadata,
};
#[cfg(feature = "fork")]
use libafl_bolts::shmem::ShMemProvider;

#[cfg(emulation_mode = "usermode")]
use crate::EmulatorModules;
#[cfg(emulation_mode = "usermode")]
use libafl_qemu_sys::{libafl_qemu_handle_crash, siginfo_t};

#[cfg(emulation_mode = "systemmode")]
use libafl_bolts::os::unix_signals::siginfo_t;
#[cfg(emulation_mode = "systemmode")]
use libafl_qemu_sys::qemu_system_debug_request;

use libafl_bolts::{
    os::unix_signals::{ucontext_t, Signal},
};

pub struct QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input, &mut Emulator<CM, EH, ET, S>) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S>,
{
    inner: StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, EH, ET, S>>,
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
    libafl_qemu_handle_crash(signal as i32, info as *mut siginfo_t, puc);
}

#[cfg(emulation_mode = "systemmode")]
pub(crate) static mut BREAK_ON_TMOUT: bool = false;

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


impl<'a, CM, EH, H, OT, ET, S> Debug for QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input, &mut Emulator<CM, EH, ET, S>) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S> + Debug,
    ET: EmulatorModuleTuple<S> + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, CM, EH, H, OT, ET, S> QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input, &mut Emulator<CM, EH, ET, S>) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    ET: EmulatorModuleTuple<S> + Debug,
{
    pub fn new<EM, OF, Z>(
        emulator: Emulator<CM, EH, ET, S>,
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
        let mut inner = StatefulInProcessExecutor::with_timeout(
            harness_fn, emulator, observers, fuzzer, state, event_mgr, timeout,
        )?;

        #[cfg(emulation_mode = "usermode")]
        {
            inner.inprocess_hooks_mut().crash_handler = inproc_qemu_crash_handler::<
                StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, EH, ET, S>>,
                EM,
                OF,
                Z,
                ET,
                S,
            > as *const c_void;

            let handler = |emulator_modules: &mut EmulatorModules<ET, S>, host_sig| {
                eprintln!("Crashed with signal {host_sig}");
                unsafe {
                    libafl::executors::inprocess::generic_inproc_crash_handler::<Self, EM, OF, Z>();
                }
                if let Some(cpu) = emulator_modules.qemu().current_cpu() {
                    eprint!("Context:\n{}", cpu.display_context());
                }
            };

            inner.exposed_executor_state_mut().modules_mut().crash_closure(Box::new(handler));
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            inner.inprocess_hooks_mut().timeout_handler = inproc_qemu_timeout_handler::<
                StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, EH, ET, S>>,
                EM,
                OF,
                Z,
            > as *const c_void;
        }

        Ok(Self { inner })
    }

    pub fn inner(
        &self,
    ) -> &StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, EH, ET, S>> {
        &self.inner
    }

    #[cfg(emulation_mode = "systemmode")]
    pub fn break_on_timeout(&mut self) {
        unsafe {
            BREAK_ON_TMOUT = true;
        }
    }

    pub fn inner_mut(
        &mut self,
    ) -> &mut StatefulInProcessExecutor<'a, H, OT, S, Emulator<CM, EH, ET, S>> {
        &mut self.inner
    }
}

impl<'a, CM, EH, EM, H, OT, OF, ET, S, Z> Executor<EM, Z>
for QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    H: FnMut(&S::Input, &mut Emulator<CM, EH, ET, S>) -> ExitKind,
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
        self.inner
            .exposed_executor_state_mut()
            .first_exec_all();

        self.inner
            .exposed_executor_state_mut()
            .pre_exec_all(input);

        let mut exit_kind = self.inner.run_target(fuzzer, state, mgr, input)?;

        self.inner
            .exposed_executor_state
            .post_exec_all(
                input,
                &mut *self.inner.inner.observers_mut(),
                &mut exit_kind,
            );

        Ok(exit_kind)
    }
}

impl<'a, CM, EH, H, OT, ET, S> UsesState for QemuExecutor<'a, CM, EH, H, OT, ET, S>
where
    CM: CommandManager<EH, ET, S>,
    EH: EmulatorExitHandler<ET, S>,
    H: FnMut(&S::Input, &mut Emulator<CM, EH, ET, S>) -> ExitKind,
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
    H: FnMut(&S::Input, &mut Emulator<CM, EH, ET, S>) -> ExitKind,
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
    H: FnMut(&S::Input, &mut Emulator<CM, EH, ET, S>) -> ExitKind,
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
    emulator: Emulator<CM, EH, ET, S>,
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
            .field("inner", &self.inner)
            .field("emulator", &self.emulator)
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
        emulator: Emulator<CM, EH, ET, S>,
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
            emulator,
        })
    }

    pub fn inner(&self) -> &InProcessForkExecutor<'a, H, OT, S, SP, EM, Z> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut InProcessForkExecutor<'a, H, OT, S, SP, EM, Z> {
        &mut self.inner
    }

    pub fn emulator(&self) -> &Emulator<CM, EH, ET, S> {
        &self.emulator
    }

    pub fn emulator_mut(&mut self) -> &Emulator<CM, EH, ET, S> {
        &mut self.emulator
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
