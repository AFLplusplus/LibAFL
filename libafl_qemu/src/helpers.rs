use libafl::{
    bolts::tuples::MatchFirstType, executors::ExitKind, inputs::Input, observers::ObserversTuple,
    state::HasMetadata,
};

use crate::{emu, executor::QemuExecutor, hooks};

// TODO remove 'static when specialization will be stable
pub trait QemuHelper<I, S>: 'static
where
    I: Input,
{
    fn init<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>;
}

pub trait QemuHelperTuple<I, S>: MatchFirstType
where
    I: Input,
{
    fn init_all<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>;
}

impl<I, S> QemuHelperTuple<I, S> for ()
where
    I: Input,
{
    fn init_all<'a, H, OT, QT>(&self, _executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
    }
}

impl<Head, Tail, I, S> QemuHelperTuple<I, S> for (Head, Tail)
where
    Head: QemuHelper<I, S>,
    Tail: QemuHelperTuple<I, S>,
    I: Input,
{
    fn init_all<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        self.0.init(executor);
        self.1.init_all(executor)
    }
}

pub struct QemuEdgeCoverageHelper {}

impl QemuEdgeCoverageHelper {
    pub fn new() -> Self {
        Self {}
    }
}

impl<I, S> QemuHelper<I, S> for QemuEdgeCoverageHelper
where
    I: Input,
    S: HasMetadata,
{
    fn init<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        executor.hook_edge_generation(hooks::gen_unique_edge_ids::<I, QT, S>);
        emu::set_exec_edge_hook(hooks::trace_edge_hitcount);
    }
}

pub struct QemuCmpLogHelper {}

impl QemuCmpLogHelper {
    pub fn new() -> Self {
        Self {}
    }
}

impl<I, S> QemuHelper<I, S> for QemuCmpLogHelper
where
    I: Input,
    S: HasMetadata,
{
    fn init<'a, H, OT, QT>(&self, executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        executor.hook_cmp_generation(hooks::gen_unique_cmp_ids::<I, QT, S>);
        emu::set_exec_cmp8_hook(hooks::trace_cmp8_cmplog);
        emu::set_exec_cmp4_hook(hooks::trace_cmp4_cmplog);
        emu::set_exec_cmp2_hook(hooks::trace_cmp2_cmplog);
        emu::set_exec_cmp1_hook(hooks::trace_cmp1_cmplog);
    }
}
