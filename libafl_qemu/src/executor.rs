//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
};

#[cfg(feature = "fork")]
use libafl::{
    events::EventManager,
    executors::InProcessForkExecutor,
    state::{HasLastReportTime, HasMetadata},
};
use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{
        inprocess::{InProcessExecutor, InProcessExecutorHandlerData},
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasSolutions, State, UsesState},
    Error,
};
use libafl_bolts::os::unix_signals::{siginfo_t, ucontext_t, Signal};
#[cfg(feature = "fork")]
use libafl_bolts::shmem::ShMemProvider;

use crate::{emu::Emulator, helper::QemuHelperTuple, hooks::QemuHooks};

pub struct QemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
{
    inner: InProcessExecutor<'a, H, OT, S>,
    hooks: &'a mut QemuHooks<'a, QT, S>,
    first_exec: bool,
}

impl<'a, H, OT, QT, S> Debug for QemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("hooks", &self.hooks)
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(emulation_mode = "usermode")]
extern "C" {
    // Original QEMU user signal handler
    fn libafl_qemu_handle_crash(signal: i32, info: *mut siginfo_t, puc: *mut c_void) -> i32;
}

#[cfg(emulation_mode = "usermode")]
static mut USE_LIBAFL_CRASH_HANDLER: bool = false;

#[cfg(emulation_mode = "usermode")]
#[no_mangle]
pub unsafe extern "C" fn libafl_executor_reinstall_handlers() {
    USE_LIBAFL_CRASH_HANDLER = true;
}

#[cfg(emulation_mode = "usermode")]
pub unsafe fn inproc_qemu_crash_handler<E, EM, OF, Z>(
    signal: Signal,
    info: &mut siginfo_t,
    mut context: Option<&mut ucontext_t>,
    data: &mut InProcessExecutorHandlerData,
) where
    E: Executor<EM, Z> + HasObservers,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasSolutions + HasClientPerfMonitor + HasCorpus,
    Z: HasObjective<Objective = OF, State = E::State>,
{
    let real_crash = if USE_LIBAFL_CRASH_HANDLER {
        true
    } else {
        let puc = match &mut context {
            Some(v) => (*v) as *mut ucontext_t as *mut c_void,
            None => core::ptr::null_mut(),
        };
        libafl_qemu_handle_crash(signal as i32, info, puc) != 0
    };
    if real_crash {
        libafl::executors::inprocess::unix_signal_handler::inproc_crash_handler::<E, EM, OF, Z>(
            signal, info, context, data,
        );
    }
}

#[cfg(emulation_mode = "systemmode")]
static mut BREAK_ON_TMOUT: bool = false;

#[cfg(emulation_mode = "systemmode")]
extern "C" {
    fn qemu_system_debug_request();
}

#[cfg(emulation_mode = "systemmode")]
pub unsafe fn inproc_qemu_timeout_handler<E, EM, OF, Z>(
    signal: Signal,
    info: &mut siginfo_t,
    context: Option<&mut ucontext_t>,
    data: &mut InProcessExecutorHandlerData,
) where
    E: Executor<EM, Z> + HasObservers,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasSolutions + HasClientPerfMonitor + HasCorpus,
    Z: HasObjective<Objective = OF, State = E::State>,
{
    if BREAK_ON_TMOUT {
        qemu_system_debug_request();
    } else {
        libafl::executors::inprocess::unix_signal_handler::inproc_timeout_handler::<E, EM, OF, Z>(
            signal, info, context, data,
        );
    }
}

impl<'a, H, OT, QT, S> QemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
{
    pub fn new<EM, OF, Z>(
        hooks: &'a mut QemuHooks<'a, QT, S>,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: State + HasExecutions + HasCorpus + HasSolutions + HasClientPerfMonitor,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let mut inner = InProcessExecutor::new(harness_fn, observers, fuzzer, state, event_mgr)?;
        #[cfg(emulation_mode = "usermode")]
        {
            inner.handlers_mut().crash_handler =
                inproc_qemu_crash_handler::<InProcessExecutor<'a, H, OT, S>, EM, OF, Z>
                    as *const c_void;
        }
        #[cfg(emulation_mode = "systemmode")]
        {
            inner.handlers_mut().timeout_handler =
                inproc_qemu_timeout_handler::<InProcessExecutor<'a, H, OT, S>, EM, OF, Z>
                    as *const c_void;
        }
        Ok(Self {
            first_exec: true,
            hooks,
            inner,
        })
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

    pub fn hooks(&self) -> &QemuHooks<'a, QT, S> {
        self.hooks
    }

    pub fn hooks_mut(&mut self) -> &mut QemuHooks<'a, QT, S> {
        self.hooks
    }

    pub fn emulator(&self) -> &Emulator {
        self.hooks.emulator()
    }
}

impl<'a, EM, H, OT, QT, S, Z> Executor<EM, Z> for QemuExecutor<'a, H, OT, QT, S>
where
    EM: UsesState<State = S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput + HasExecutions,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        let emu = Emulator::new_empty();
        if self.first_exec {
            self.hooks.helpers().first_exec_all(self.hooks);
            self.first_exec = false;
        }
        self.hooks.helpers_mut().pre_exec_all(&emu, input);
        let mut exit_kind = self.inner.run_target(fuzzer, state, mgr, input)?;
        self.hooks.helpers_mut().post_exec_all(
            &emu,
            input,
            self.inner.observers_mut(),
            &mut exit_kind,
        );
        Ok(exit_kind)
    }
}

impl<'a, H, OT, QT, S> UsesState for QemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    S: UsesInput,
{
    type State = S;
}

impl<'a, H, OT, QT, S> UsesObservers for QemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    S: UsesInput,
{
    type Observers = OT;
}

impl<'a, H, OT, QT, S> HasObservers for QemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.inner.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.inner.observers_mut()
    }
}

#[cfg(feature = "fork")]
pub struct QemuForkExecutor<'a, H, OT, QT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    SP: ShMemProvider,
{
    first_exec: bool,
    hooks: &'a mut QemuHooks<'a, QT, S>,
    inner: InProcessForkExecutor<'a, H, OT, S, SP>,
}

#[cfg(feature = "fork")]
impl<'a, H, OT, QT, S, SP> Debug for QemuForkExecutor<'a, H, OT, QT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    SP: ShMemProvider,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuForkExecutor")
            .field("hooks", &self.hooks)
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(feature = "fork")]
impl<'a, H, OT, QT, S, SP> QemuForkExecutor<'a, H, OT, QT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    SP: ShMemProvider,
{
    pub fn new<EM, OF, Z>(
        hooks: &'a mut QemuHooks<'a, QT, S>,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: HasSolutions + HasClientPerfMonitor,
        Z: HasObjective<Objective = OF, State = S>,
    {
        assert!(!QT::HOOKS_DO_SIDE_EFFECTS, "When using QemuForkExecutor, the hooks must not do any side effect as they will happen in the child process and then discarded");

        Ok(Self {
            first_exec: true,
            hooks,
            inner: InProcessForkExecutor::new(
                harness_fn,
                observers,
                fuzzer,
                state,
                event_mgr,
                shmem_provider,
            )?,
        })
    }

    pub fn inner(&self) -> &InProcessForkExecutor<'a, H, OT, S, SP> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut InProcessForkExecutor<'a, H, OT, S, SP> {
        &mut self.inner
    }

    pub fn hooks(&self) -> &QemuHooks<'a, QT, S> {
        self.hooks
    }

    pub fn hooks_mut(&mut self) -> &mut QemuHooks<'a, QT, S> {
        self.hooks
    }

    pub fn emulator(&self) -> &Emulator {
        self.hooks.emulator()
    }
}

#[cfg(feature = "fork")]
impl<'a, EM, H, OT, QT, S, Z, SP> Executor<EM, Z> for QemuForkExecutor<'a, H, OT, QT, S, SP>
where
    EM: EventManager<InProcessForkExecutor<'a, H, OT, S, SP>, Z, State = S>,
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput + HasClientPerfMonitor + HasMetadata + HasExecutions + HasLastReportTime,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        let emu = Emulator::new_empty();
        if self.first_exec {
            self.hooks.helpers().first_exec_all(self.hooks);
            self.first_exec = false;
        }
        self.hooks.helpers_mut().pre_exec_all(&emu, input);
        let mut exit_kind = self.inner.run_target(fuzzer, state, mgr, input)?;
        self.hooks.helpers_mut().post_exec_all(
            &emu,
            input,
            self.inner.observers_mut(),
            &mut exit_kind,
        );
        Ok(exit_kind)
    }
}

#[cfg(feature = "fork")]
impl<'a, H, OT, QT, S, SP> UsesObservers for QemuForkExecutor<'a, H, OT, QT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    S: UsesInput,
    SP: ShMemProvider,
{
    type Observers = OT;
}

#[cfg(feature = "fork")]
impl<'a, H, OT, QT, S, SP> UsesState for QemuForkExecutor<'a, H, OT, QT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    S: UsesInput,
    SP: ShMemProvider,
{
    type State = S;
}

#[cfg(feature = "fork")]
impl<'a, H, OT, QT, S, SP> HasObservers for QemuForkExecutor<'a, H, OT, QT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    SP: ShMemProvider,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.inner.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.inner.observers_mut()
    }
}
