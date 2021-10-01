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

    fn pre_exec(&mut self, _input: &I) {}

    fn post_exec(&mut self, _input: &I) {}
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

    fn pre_exec_all(&mut self, input: &I);

    fn post_exec_all(&mut self, input: &I);
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

    fn pre_exec_all(&mut self, _input: &I) {}

    fn post_exec_all(&mut self, _input: &I) {}
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

    fn pre_exec_all(&mut self, input: &I) {
        self.0.pre_exec(input);
        self.1.pre_exec_all(input)
    }

    fn post_exec_all(&mut self, input: &I) {
        self.0.post_exec(input);
        self.1.post_exec_all(input)
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
    pub dirty: Vec<u64>,
    pub brk: u64,
    pub empty: bool,
}

impl QemuSnapshotHelper {
    pub fn new() -> Self {
        Self {
            access_cache: [u64::MAX; 4],
            access_cache_idx: 0,
            pages: HashMap::default(),
            dirty: vec![],
            brk: 0,
            empty: true,
        }
    }

    pub fn snapshot(&mut self) {
        self.brk = emu::get_brk();
        self.pages.clear();
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
                self.pages.insert(addr, info);
                addr += SNAPSHOT_PAGE_SIZE as u64;
            }
        }
        self.empty = false;
    }

    pub fn page_access(&mut self, page: u64) {
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
            if info.dirty {
                return;
            }
            info.dirty = true;
        }
        self.dirty.push(page);
    }

    pub fn access(&mut self, addr: u64, size: usize) {
        debug_assert!(size > 0);
        let page = addr & (SNAPSHOT_PAGE_SIZE as u64 - 1);
        self.page_access(page);
        let second_page = (addr + size as u64 - 1) & (SNAPSHOT_PAGE_SIZE as u64 - 1);
        if page != second_page {
            self.page_access(second_page);
        }
    }

    pub fn reset(&mut self) {
        self.access_cache = [u64::MAX; 4];
        self.access_cache_idx = 0;
        for page in self.dirty.pop() {
            if let Some(info) = self.pages.get_mut(&page) {
                emu::write_mem(page, &info.data);
                info.dirty = false;
            }
        }
        emu::set_brk(self.brk);
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

    fn pre_exec(&mut self, _input: &I) {
        if self.empty {
            self.snapshot();
        } else {
            self.reset();
        }
    }
}
