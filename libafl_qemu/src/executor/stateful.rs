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
use libafl_bolts::tuples::RefIndexable;

#[cfg(emulation_mode = "usermode")]
use crate::executor::inproc_qemu_crash_handler;
#[cfg(emulation_mode = "systemmode")]
use crate::executor::{inproc_qemu_timeout_handler, BREAK_ON_TMOUT};
use crate::{
    command::CommandManager, executor::QemuExecutorState, Emulator, EmulatorExitHandler,
    EmulatorToolTuple,
};

pub struct StatefulQemuExecutor<'a, CM, EH, H, OT, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, CM, EH, QT, S>) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    QT: EmulatorToolTuple<S>,
{
    inner: StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, CM, EH, QT, S>>,
}

impl<'a, CM, EH, H, OT, QT, S> Debug for StatefulQemuExecutor<'a, CM, EH, H, OT, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, CM, EH, QT, S>) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S> + Debug,
    QT: EmulatorToolTuple<S> + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, CM, EH, H, OT, QT, S> StatefulQemuExecutor<'a, CM, EH, H, OT, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, CM, EH, QT, S>) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    QT: EmulatorToolTuple<S> + Debug,
{
    pub fn new<EM, OF, Z>(
        emulator: &'a mut Emulator<CM, EH, QT, S>,
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
        Z: HasObjective<Objective = OF, State = S>,
    {
        let qemu_state = QemuExecutorState::new::<
            StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, CM, EH, QT, S>>,
            EM,
            OF,
            OT,
            Z,
        >(emulator)?;

        let mut inner = StatefulInProcessExecutor::with_timeout(
            harness_fn, qemu_state, observers, fuzzer, state, event_mgr, timeout,
        )?;

        #[cfg(emulation_mode = "usermode")]
        {
            inner.inprocess_hooks_mut().crash_handler = inproc_qemu_crash_handler::<
                StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, CM, EH, QT, S>>,
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
                StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, CM, EH, QT, S>>,
                EM,
                OF,
                Z,
            > as *const c_void;
        }

        Ok(Self { inner })
    }

    pub fn inner(
        &self,
    ) -> &StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, CM, EH, QT, S>> {
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
    ) -> &mut StatefulInProcessExecutor<'a, H, OT, S, QemuExecutorState<'a, CM, EH, QT, S>> {
        &mut self.inner
    }
}

impl<'a, CM, EH, EM, H, OT, OF, QT, S, Z> Executor<EM, Z>
    for StatefulQemuExecutor<'a, CM, EH, H, OT, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    EM: EventFirer<State = S> + EventRestarter<State = S>,
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, CM, EH, QT, S>) -> ExitKind,
    S: Unpin + State + HasExecutions + HasCorpus + HasSolutions,
    OT: ObserversTuple<S>,
    OF: Feedback<S>,
    QT: EmulatorToolTuple<S> + Debug,
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
            .pre_exec::<Self, EM, OF, Z>(input);
        let mut exit_kind = self.inner.run_target(fuzzer, state, mgr, input)?;
        self.inner
            .exposed_executor_state
            .post_exec::<Self, EM, OT, OF, Z>(
                input,
                &mut *self.inner.inner.observers_mut(),
                &mut exit_kind,
            );
        Ok(exit_kind)
    }
}

impl<'a, CM, EH, H, OT, QT, S> UsesState for StatefulQemuExecutor<'a, CM, EH, H, OT, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, CM, EH, QT, S>) -> ExitKind,
    OT: ObserversTuple<S>,
    QT: EmulatorToolTuple<S>,
    S: Unpin + State + HasExecutions,
{
    type State = S;
}

impl<'a, CM, EH, H, OT, QT, S> UsesObservers for StatefulQemuExecutor<'a, CM, EH, H, OT, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, CM, EH, QT, S>) -> ExitKind,
    OT: ObserversTuple<S>,
    QT: EmulatorToolTuple<S>,
    S: Unpin + State + HasExecutions,
{
    type Observers = OT;
}

impl<'a, CM, EH, H, OT, QT, S> HasObservers for StatefulQemuExecutor<'a, CM, EH, H, OT, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    H: FnMut(&S::Input, &mut QemuExecutorState<'a, CM, EH, QT, S>) -> ExitKind,
    S: Unpin + State + HasExecutions,
    OT: ObserversTuple<S>,
    QT: EmulatorToolTuple<S>,
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
