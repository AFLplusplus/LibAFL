//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    time::Duration,
};

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
    Error,
};

#[cfg(emulation_mode = "usermode")]
use crate::executor::inproc_qemu_crash_handler;
#[cfg(emulation_mode = "systemmode")]
use crate::executor::{inproc_qemu_timeout_handler, BREAK_ON_TMOUT};
use crate::{
    emu::Emulator, executor::QemuExecutorState, helper::QemuHelperTuple, hooks::QemuHooks,
};

pub struct StatefulQemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
    S: State + HasExecutions,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
{
    inner: StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, QT, S>>,
}

impl<'a, H, OT, QT, S> Debug for StatefulQemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
    S: State + HasExecutions,
    OT: ObserversTuple<S> + Debug,
    QT: QemuHelperTuple<S> + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, H, OT, QT, S> StatefulQemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
    S: State + HasExecutions,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S> + Debug,
{
    pub fn new<EM, OF, Z>(
        hooks: &'a mut QemuHooks<QT, S>,
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
        S: State + HasExecutions + HasCorpus + HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let qemu_state = QemuExecutorState::new::<
            StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, QT, S>>,
            EM,
            OF,
            OT,
            Z,
        >(hooks)?;

        let mut inner = StatefulInProcessExecutor::with_timeout(
            harness_fn, qemu_state, observers, fuzzer, state, event_mgr, timeout,
        )?;

        #[cfg(emulation_mode = "usermode")]
        {
            inner.inprocess_hooks_mut().crash_handler = inproc_qemu_crash_handler::<
                StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, QT, S>>,
                EM,
                OF,
                Z,
                QT,
                S,
            > as *const c_void;
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            inner.inprocess_hooks_mut().timeout_handler = inproc_qemu_timeout_handler::<
                StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, QT, S>>,
                EM,
                OF,
                Z,
            > as *const c_void;
        }

        Ok(Self { inner })
    }

    pub fn inner(&self) -> &StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, QT, S>> {
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
    ) -> &mut StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, QT, S>> {
        &mut self.inner
    }

    pub fn hooks(&self) -> &QemuHooks<QT, S> {
        self.inner.exposed_executor_state().hooks()
    }

    pub fn hooks_mut(&mut self) -> &mut QemuHooks<QT, S> {
        self.inner.exposed_executor_state_mut().hooks_mut()
    }

    pub fn emulator(&self) -> &Emulator {
        self.inner.exposed_executor_state().emulator()
    }
}

impl<'a, EM, H, OT, OF, QT, S, Z> Executor<EM, Z> for StatefulQemuExecutor<'a, H, OT, QT, S>
where
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
    S: State + HasExecutions + HasCorpus + HasSolutions,
    OT: ObserversTuple<S>,
    OF: Feedback<S>,
    QT: QemuHelperTuple<S> + Debug,
    Z: HasObjective<Objective = OF, State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        let emu = Emulator::get().unwrap();
        self.inner
            .exposed_executor_state_mut()
            .pre_exec::<Self, EM, OF, Z>(input, &emu);
        let mut exit_kind = self.inner.run_target(fuzzer, state, mgr, input)?;
        self.inner
            .exposed_executor_state
            .post_exec::<Self, EM, OT, OF, Z>(
                input,
                &emu,
                self.inner.inner.observers_mut(),
                &mut exit_kind,
            );
        Ok(exit_kind)
    }
}

impl<'a, H, OT, QT, S> UsesState for StatefulQemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    type State = S;
}

impl<'a, H, OT, QT, S> UsesObservers for StatefulQemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
    OT: ObserversTuple<S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    type Observers = OT;
}

impl<'a, H, OT, QT, S> HasObservers for StatefulQemuExecutor<'a, H, OT, QT, S>
where
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
    S: State + HasExecutions,
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
