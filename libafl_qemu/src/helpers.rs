use std::collections::HashMap;

use libafl::{
    bolts::tuples::MatchFirstType, executors::ExitKind, inputs::Input, observers::ObserversTuple,
    state::HasMetadata,
};

use crate::{emu, emu::GuestMaps, executor::QemuExecutor, hooks};

// TODO remove 'static when specialization will be stable
pub trait QemuHelper<I, S>: 'static
where
    I: Input,
{
    fn init<'a, H, OT, QT>(&self, _executor: &QemuExecutor<'a, H, I, OT, QT, S>)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
    }

    fn pre_exec<'a, H, OT, QT>(&mut self, _executor: &QemuExecutor<'a, H, I, OT, QT, S>, _input: &I)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
    }

    fn post_exec<'a, H, OT, QT>(
        &mut self,
        _executor: &QemuExecutor<'a, H, I, OT, QT, S>,
        _input: &I,
    ) where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
    }
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

    fn pre_exec_all<'a, H, OT, QT>(
        &mut self,
        executor: &QemuExecutor<'a, H, I, OT, QT, S>,
        input: &I,
    ) where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>;

    fn post_exec_all<'a, H, OT, QT>(
        &mut self,
        executor: &QemuExecutor<'a, H, I, OT, QT, S>,
        input: &I,
    ) where
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

    fn pre_exec_all<'a, H, OT, QT>(
        &mut self,
        _executor: &QemuExecutor<'a, H, I, OT, QT, S>,
        _input: &I,
    ) where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
    }

    fn post_exec_all<'a, H, OT, QT>(
        &mut self,
        _executor: &QemuExecutor<'a, H, I, OT, QT, S>,
        _input: &I,
    ) where
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

    fn pre_exec_all<'a, H, OT, QT>(
        &mut self,
        executor: &QemuExecutor<'a, H, I, OT, QT, S>,
        input: &I,
    ) where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        self.0.pre_exec(executor, input);
        self.1.pre_exec_all(executor, input)
    }

    fn post_exec_all<'a, H, OT, QT>(
        &mut self,
        executor: &QemuExecutor<'a, H, I, OT, QT, S>,
        input: &I,
    ) where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        self.0.post_exec(executor, input);
        self.1.post_exec_all(executor, input)
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

pub const SNAPSHOT_PAGE_SIZE: usize = 4096;

pub struct SnapshotPageInfo {
    pub addr: u64,
    pub dirty: bool,
    pub data: [u8; SNAPSHOT_PAGE_SIZE],
}

// TODO be thread-safe maybe with https://amanieu.github.io/thread_local-rs/thread_local/index.html
pub struct QemuSnapshotHelper {
    pub access_cache: [u64; 4],
    pub access_cache_idx: usize,
    pub pages: HashMap<u64, SnapshotPageInfo>,
}

impl QemuSnapshotHelper {
    pub fn new() -> Self {
        let mut pages = HashMap::default();
        for map in GuestMaps::new() {
            // TODO track all the pages OR track mproctect
            if !map.flags().is_w() {
                continue;
            }
            let mut addr = map.start();
            while addr < map.end() {
                let mut info = SnapshotPageInfo {
                    addr,
                    dirty: false,
                    data: [0; SNAPSHOT_PAGE_SIZE],
                };
                emu::read_mem(addr, &mut info.data);
                pages.insert(addr, info);
                addr += SNAPSHOT_PAGE_SIZE as u64;
            }
        }
        Self {
            access_cache: [u64::MAX; 4],
            access_cache_idx: 0,
            pages,
        }
    }

    pub fn access(&mut self, addr: u64, size: usize) {
        let page = addr & (SNAPSHOT_PAGE_SIZE as u64 - 1);
        if self.access_cache[0] == page
            || self.access_cache[1] == page
            || self.access_cache[2] == page
            || self.access_cache[3] == page
        {
            return;
        }
        self.access_cache[self.access_cache_idx] = page;
        self.access_cache_idx = (self.access_cache_idx + 1) & 3;
        if let Some(info) = self.pages.get_mut(&page) {
            info.dirty = true;
        }
    }

    pub fn reset(&mut self) {
        for (page, info) in self.pages.iter_mut() {
            if info.dirty {
                emu::write_mem(*page, &info.data);
                info.dirty = false;
            }
        }
    }
}

impl<I, S> QemuHelper<I, S> for QemuSnapshotHelper
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
        executor.hook_write8_execution(hooks::trace_write8_snapshot::<I, QT, S>);
        executor.hook_write4_execution(hooks::trace_write4_snapshot::<I, QT, S>);
        executor.hook_write2_execution(hooks::trace_write2_snapshot::<I, QT, S>);
        executor.hook_write1_execution(hooks::trace_write1_snapshot::<I, QT, S>);
        executor.hook_write_n_execution(hooks::trace_write_n_snapshot::<I, QT, S>);
    }

    fn pre_exec<'a, H, OT, QT>(&mut self, _executor: &QemuExecutor<'a, H, I, OT, QT, S>, _input: &I)
    where
        H: FnMut(&I) -> ExitKind,
        OT: ObserversTuple<I, S>,
        QT: QemuHelperTuple<I, S>,
    {
        self.reset();
    }
}
