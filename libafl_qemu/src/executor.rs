//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
use core::fmt::{self, Debug, Formatter};

#[cfg(feature = "fork")]
use libafl::{
    bolts::shmem::ShMemProvider, events::EventManager, executors::InProcessForkExecutor,
    state::HasMetadata,
};
use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasSolutions, State, UsesState},
    Error,
};

use crate::{emu::Emulator, helper::QemuHelperTuple, hooks::QemuHooks};

pub struct QemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input) -> ExitKind,
    S: UsesInput,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
{
    first_exec: bool,
    hooks: &'a mut QemuHooks<'a, QT, S>,
    inner: InProcessExecutor<'a, H, OT, S>,
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
        Ok(Self {
            first_exec: true,
            hooks,
            inner: InProcessExecutor::new(harness_fn, observers, fuzzer, state, event_mgr)?,
        })
    }

    pub fn inner(&self) -> &InProcessExecutor<'a, H, OT, S> {
        &self.inner
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
    S: UsesInput,
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
    S: UsesInput + HasClientPerfMonitor + HasMetadata + HasExecutions,
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
