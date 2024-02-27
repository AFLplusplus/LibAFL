//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
use core::{
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    time::Duration,
};
use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{
        inprocess::{with_state::InProcessExecutorWithState, HasInProcessHooks},
        Executor, ExitKind, HasObservers, NopExecutorState,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    observers::{ObserversTuple, UsesObservers},
    state::{HasCorpus, HasExecutions, HasSolutions, State, UsesState},
    Error,
};

use crate::{emu::Emulator, helper::QemuHelperTuple, hooks::QemuHooks, executor::{QemuExecutorState, inproc_qemu_crash_handler}};

pub struct QemuExecutorWithState<'a, H, OT, QT, S>
    where
        H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
        S: State + HasExecutions,
        OT: ObserversTuple<S>,
        QT: QemuHelperTuple<S>,
{
    inner: InProcessExecutorWithState<'a, H, OT, S, QemuExecutorState<'a, QT, S>>,
    state: QemuExecutorState<'a, QT, S>,
}

impl<'a, H, OT, QT, S> Debug for QemuExecutorWithState<'a, H, OT, QT, S>
    where
        H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
        S: State + HasExecutions,
        OT: ObserversTuple<S> + Debug,
        QT: QemuHelperTuple<S> + Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("hooks", &self.state.hooks)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, H, OT, QT, S> QemuExecutorWithState<'a, H, OT, QT, S>
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
        let mut inner = InProcessExecutorWithState::with_timeout(
            harness_fn, observers, fuzzer, state, event_mgr, timeout,
        )?;

        #[cfg(emulation_mode = "usermode")]
        {
            inner.inprocess_hooks_mut().crash_handler = inproc_qemu_crash_handler::<
                InProcessExecutorWithState<'a, H, OT, S, QemuExecutorState<'a, QT, S>>,
                EM,
                QemuExecutorState<'a, QT, S>,
                OF,
                Z,
                QT,
                S,
            > as *const c_void;
        }

        #[cfg(emulation_mode = "systemmode")]
        {
            inner.inprocess_hooks_mut().timeout_handler = inproc_qemu_timeout_handler::<
                InProcessExecutorWithState<'a, H, OT, S, QemuExecutorState<'a, QT, S>>,
                EM,
                QemuExecutorState<'a, QT, S>,
                OF,
                Z,
            > as *const c_void;
        }

        let state = QemuExecutorState::new::<
            InProcessExecutorWithState<'a, H, OT, S, QemuExecutorState<'a, QT, S>>,
            QemuExecutorState<'a, QT, S>,
            EM,
            OF,
            OT,
            Z,
        >(hooks)?;

        Ok(Self { inner, state })
    }

    pub fn inner(&self) -> &InProcessExecutorWithState<'a, H, OT, S, QemuExecutorState<'a, QT, S>> {
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
    ) -> &mut InProcessExecutorWithState<'a, H, OT, S, QemuExecutorState<'a, QT, S>> {
        &mut self.inner
    }

    pub fn hooks(&self) -> &QemuHooks<QT, S> {
        self.state.hooks()
    }

    pub fn hooks_mut(&mut self) -> &mut QemuHooks<QT, S> {
        self.state.hooks_mut()
    }

    pub fn emulator(&self) -> &Emulator {
        self.state.emulator()
    }
}

impl<'a, EM, H, OT, OF, QT, S, Z> Executor<EM, Z, NopExecutorState>
for QemuExecutorWithState<'a, H, OT, QT, S>
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
        _executor_state: &mut (),
    ) -> Result<ExitKind, Error> {
        let emu = Emulator::get().unwrap();
        self.state.pre_exec::<Self, EM, OT, OF, Z>(input, &emu);
        let mut exit_kind = self
            .inner
            .run_target(fuzzer, state, mgr, input, &mut self.state)?;
        self.state.post_exec::<Self, EM, OT, OF, Z>(
            input,
            &emu,
            self.inner.observers_mut(),
            &mut exit_kind,
        );
        Ok(exit_kind)
    }
}

impl<'a, H, OT, QT, S> UsesState for QemuExecutorWithState<'a, H, OT, QT, S>
    where
        H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
        OT: ObserversTuple<S>,
        QT: QemuHelperTuple<S>,
        S: State + HasExecutions,
{
    type State = S;
}

impl<'a, H, OT, QT, S> UsesObservers for QemuExecutorWithState<'a, H, OT, QT, S>
    where
        H: FnMut(&S::Input, &mut QemuExecutorState<'a, QT, S>) -> ExitKind,
        OT: ObserversTuple<S>,
        QT: QemuHelperTuple<S>,
        S: State + HasExecutions,
{
    type Observers = OT;
}

impl<'a, H, OT, QT, S> HasObservers for QemuExecutorWithState<'a, H, OT, QT, S>
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

