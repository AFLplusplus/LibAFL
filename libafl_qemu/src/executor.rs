//! A `QEMU`-based executor for binary-only instrumentation in `LibAFL`
use core::{
    fmt::{self, Debug, Formatter},
    pin::Pin,
};

use libafl::{
    events::{EventFirer, EventRestarter},
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::Input,
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasSolutions},
    Error,
};

pub use crate::emu::SyscallHookResult;
use crate::{emu::Emulator, helper::QemuHelperTuple, hooks::QemuHooks};

pub struct QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
{
    hooks: Pin<Box<QemuHooks<'a, I, QT, S>>>,
    inner: InProcessExecutor<'a, H, I, OT, S>,
}

impl<'a, H, I, OT, QT, S> Debug for QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuExecutor")
            .field("hooks", &self.hooks)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, H, I, OT, QT, S> QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
{
    pub fn new<EM, OF, Z>(
        hooks: Pin<Box<QemuHooks<'a, I, QT, S>>>,
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<I> + EventRestarter<S>,
        OF: Feedback<I, S>,
        S: HasSolutions<I> + HasClientPerfMonitor,
        Z: HasObjective<I, OF, S>,
    {
        Ok(Self {
            hooks,
            inner: InProcessExecutor::new(harness_fn, observers, fuzzer, state, event_mgr)?,
        })
    }

    pub fn inner(&self) -> &InProcessExecutor<'a, H, I, OT, S> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut InProcessExecutor<'a, H, I, OT, S> {
        &mut self.inner
    }

    pub fn hooks(&self) -> &Pin<Box<QemuHooks<'a, I, QT, S>>> {
        &self.hooks
    }

    pub fn hooks_mut(&mut self) -> &mut Pin<Box<QemuHooks<'a, I, QT, S>>> {
        &mut self.hooks
    }

    pub fn emulator(&self) -> &Emulator {
        self.hooks.emulator()
    }
}

impl<'a, EM, H, I, OT, QT, S, Z> Executor<EM, I, S, Z> for QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let emu = Emulator::new_empty();
        unsafe {
            self.hooks
                .as_mut()
                .get_unchecked_mut()
                .helpers_mut()
                .pre_exec_all(&emu, input)
        };
        let r = self.inner.run_target(fuzzer, state, mgr, input);
        unsafe {
            self.hooks
                .as_mut()
                .get_unchecked_mut()
                .helpers_mut()
                .post_exec_all(&emu, input)
        };
        r
    }
}

impl<'a, H, I, OT, QT, S> HasObservers<I, OT, S> for QemuExecutor<'a, H, I, OT, QT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    QT: QemuHelperTuple<I, S>,
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
