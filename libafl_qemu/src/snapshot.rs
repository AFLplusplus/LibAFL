use libafl::{executors::ExitKind, inputs::Input, observers::ObserversTuple, state::HasMetadata};
use std::collections::HashMap;

use crate::{
    emu::Emulator,
    executor::QemuExecutor,
    helper::{QemuHelper, QemuHelperTuple},
    SYS_mmap, SYS_mremap,
};

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
    pub new_maps: Vec<(u64, usize)>,
    pub empty: bool,
}

impl QemuSnapshotHelper {
    #[must_use]
    pub fn new() -> Self {
        Self {
            access_cache: [u64::MAX; 4],
            access_cache_idx: 0,
            pages: HashMap::default(),
            dirty: vec![],
            brk: 0,
            new_maps: vec![],
            empty: true,
        }
    }

    pub fn snapshot(&mut self, emulator: &Emulator) {
        self.brk = emulator.get_brk();
        self.pages.clear();
        for map in emulator.mappings() {
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
                unsafe { emulator.read_mem(addr, &mut info.data) };
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

    pub fn reset(&mut self, emulator: &Emulator) {
        self.access_cache = [u64::MAX; 4];
        self.access_cache_idx = 0;
        while let Some(page) = self.dirty.pop() {
            if let Some(info) = self.pages.get_mut(&page) {
                unsafe { emulator.write_mem(page, &info.data) };
                info.dirty = false;
            }
        }
        emulator.set_brk(self.brk);
        self.reset_maps(emulator);
    }

    pub fn add_mapped(&mut self, start: u64, size: usize) {
        self.new_maps.push((start, size));
    }

    pub fn reset_maps(&mut self, emulator: &Emulator) {
        for (addr, size) in &self.new_maps {
            drop(emulator.unmap(*addr, *size));
        }
        self.new_maps.clear();
    }
}

impl Default for QemuSnapshotHelper {
    fn default() -> Self {
        Self::new()
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
        executor.hook_write8_execution(trace_write8_snapshot::<I, QT, S>);
        executor.hook_write4_execution(trace_write4_snapshot::<I, QT, S>);
        executor.hook_write2_execution(trace_write2_snapshot::<I, QT, S>);
        executor.hook_write1_execution(trace_write1_snapshot::<I, QT, S>);
        executor.hook_write_n_execution(trace_write_n_snapshot::<I, QT, S>);

        executor.hook_after_syscalls(trace_mmap_snapshot::<I, QT, S>);
    }

    fn pre_exec(&mut self, emulator: &Emulator, _input: &I) {
        if self.empty {
            self.snapshot(emulator);
        } else {
            self.reset(emulator);
        }
    }
}

pub fn trace_write1_snapshot<I, QT, S>(
    _emulator: &Emulator,
    helpers: &mut QT,
    _state: &mut S,
    _id: u64,
    addr: u64,
) where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers
        .match_first_type_mut::<QemuSnapshotHelper>()
        .unwrap();
    h.access(addr, 1);
}

pub fn trace_write2_snapshot<I, QT, S>(
    _emulator: &Emulator,
    helpers: &mut QT,
    _state: &mut S,
    _id: u64,
    addr: u64,
) where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers
        .match_first_type_mut::<QemuSnapshotHelper>()
        .unwrap();
    h.access(addr, 2);
}

pub fn trace_write4_snapshot<I, QT, S>(
    _emulator: &Emulator,
    helpers: &mut QT,
    _state: &mut S,
    _id: u64,
    addr: u64,
) where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers
        .match_first_type_mut::<QemuSnapshotHelper>()
        .unwrap();
    h.access(addr, 4);
}

pub fn trace_write8_snapshot<I, QT, S>(
    _emulator: &Emulator,
    helpers: &mut QT,
    _state: &mut S,
    _id: u64,
    addr: u64,
) where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers
        .match_first_type_mut::<QemuSnapshotHelper>()
        .unwrap();
    h.access(addr, 8);
}

pub fn trace_write_n_snapshot<I, QT, S>(
    _emulator: &Emulator,
    helpers: &mut QT,
    _state: &mut S,
    _id: u64,
    addr: u64,
    size: usize,
) where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    let h = helpers
        .match_first_type_mut::<QemuSnapshotHelper>()
        .unwrap();
    h.access(addr, size);
}

#[allow(clippy::too_many_arguments)]
pub fn trace_mmap_snapshot<I, QT, S>(
    _emulator: &Emulator,
    helpers: &mut QT,
    _state: &mut S,
    result: u64,
    sys_num: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    _a3: u64,
    _a4: u64,
    _a5: u64,
    _a6: u64,
    _a7: u64,
) -> u64
where
    I: Input,
    QT: QemuHelperTuple<I, S>,
{
    if result == u64::MAX
    /* -1 */
    {
        return result;
    }
    if i64::from(sys_num) == SYS_mmap {
        let h = helpers
            .match_first_type_mut::<QemuSnapshotHelper>()
            .unwrap();
        h.add_mapped(result, a1 as usize);
    } else if i64::from(sys_num) == SYS_mremap {
        let h = helpers
            .match_first_type_mut::<QemuSnapshotHelper>()
            .unwrap();
        h.add_mapped(a0, a2 as usize);
    }
    result
}
