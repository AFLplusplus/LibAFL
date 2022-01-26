use bio::data_structures::interval_tree::IntervalTree;
use libafl::{executors::ExitKind, inputs::Input, observers::ObserversTuple, state::HasMetadata};
use std::{
    cell::UnsafeCell,
    collections::{HashMap, HashSet},
    sync::Mutex,
};
use thread_local::ThreadLocal;

use crate::{
    emu::{Emulator, MmapPerms},
    executor::QemuExecutor,
    helper::{QemuHelper, QemuHelperTuple},
    SYS_mmap, SYS_mprotect, SYS_mremap,
};

pub const SNAPSHOT_PAGE_SIZE: usize = 4096;

#[derive(Debug)]
pub struct SnapshotPageInfo {
    pub addr: u64,
    pub perms: MmapPerms,
    pub private: bool,
    pub data: Option<Box<[u8; SNAPSHOT_PAGE_SIZE]>>,
}

#[derive(Default, Debug)]
pub struct SnapshotAccessInfo {
    pub access_cache: [u64; 4],
    pub access_cache_idx: usize,
    pub dirty: HashSet<u64>,
}

impl SnapshotAccessInfo {
    pub fn clear(&mut self) {
        self.access_cache_idx = 0;
        self.access_cache = [u64::MAX; 4];
        self.dirty.clear();
    }
}

#[derive(Debug)]
pub struct QemuSnapshotHelper {
    pub accesses: ThreadLocal<UnsafeCell<SnapshotAccessInfo>>,
    pub new_maps: Mutex<IntervalTree<u64, Option<MmapPerms>>>,
    pub pages: HashMap<u64, SnapshotPageInfo>,
    pub brk: u64,
    pub empty: bool,
}

impl QemuSnapshotHelper {
    #[must_use]
    pub fn new() -> Self {
        Self {
            accesses: ThreadLocal::new(),
            new_maps: Mutex::new(IntervalTree::new()),
            pages: HashMap::default(),
            brk: 0,
            empty: true,
        }
    }

    #[allow(clippy::uninit_assumed_init)]
    pub fn snapshot(&mut self, emulator: &Emulator) {
        self.brk = emulator.get_brk();
        self.pages.clear();
        for map in emulator.mappings() {
            let mut addr = map.start();
            while addr < map.end() {
                let mut info = SnapshotPageInfo {
                    addr,
                    perms: map.flags(),
                    private: map.is_priv(),
                    data: None,
                };
                if map.flags().is_w() {
                    unsafe {
                        info.data = Some(Box::new(core::mem::MaybeUninit::uninit().assume_init()));
                        emulator.read_mem(addr, &mut info.data.as_mut().unwrap()[..]);
                    }
                }
                self.pages.insert(addr, info);
                addr += SNAPSHOT_PAGE_SIZE as u64;
            }
        }
        self.empty = false;
    }

    pub fn page_access(&mut self, page: u64) {
        unsafe {
            let acc = self.accesses.get_or_default().get();
            if (*acc).access_cache[0] == page
                || (*acc).access_cache[1] == page
                || (*acc).access_cache[2] == page
                || (*acc).access_cache[3] == page
            {
                return;
            }
            let idx = (*acc).access_cache_idx;
            (*acc).access_cache[idx] = page;
            (*acc).access_cache_idx = (idx + 1) & 3;
            (*acc).dirty.insert(page);
        }
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
        self.reset_maps(emulator);
        for acc in self.accesses.iter_mut() {
            for page in unsafe { &(*acc.get()).dirty } {
                if let Some(info) = self.pages.get_mut(page) {
                    // TODO avoid duplicated memcpy
                    if let Some(data) = info.data.as_ref() {
                        unsafe { emulator.write_mem(*page, &data[..]) };
                    }
                }
            }
            unsafe { (*acc.get()).clear() };
        }
        emulator.set_brk(self.brk);
    }

    pub fn add_mapped(&mut self, start: u64, mut size: usize, perms: Option<MmapPerms>) {
        if size % SNAPSHOT_PAGE_SIZE != 0 {
            size = size + (SNAPSHOT_PAGE_SIZE - size % SNAPSHOT_PAGE_SIZE);
        }
        self.new_maps
            .lock()
            .unwrap()
            .insert(start..start + (size as u64), perms);
    }

    pub fn reset_maps(&mut self, emulator: &Emulator) {
        let new_maps = self.new_maps.get_mut().unwrap();
        for r in new_maps.find(0..u64::MAX) {
            let addr = r.interval().start;
            let end = r.interval().end;
            let perms = r.data();
            let mut page = addr & (SNAPSHOT_PAGE_SIZE as u64 - 1);
            let mut prev = None;
            while page < end {
                if let Some(info) = self.pages.get(&page) {
                    if let Some((addr, size)) = prev {
                        drop(emulator.unmap(addr, size));
                    }
                    prev = None;
                    if let Some(p) = perms {
                        if info.perms != *p {
                            emulator.mprotect(page, SNAPSHOT_PAGE_SIZE, info.perms);
                        }
                    }
                } else if let Some((_, size)) = &mut prev {
                    *size += SNAPSHOT_PAGE_SIZE;
                } else {
                    prev = Some((page, SNAPSHOT_PAGE_SIZE));
                }
                page += SNAPSHOT_PAGE_SIZE as u64;
            }
            if let Some((addr, size)) = prev {
                drop(emulator.unmap(addr, size));
            }
        }
        *new_maps = IntervalTree::new();
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
        if let Ok(prot) = MmapPerms::try_from(a2 as i32) {
            let h = helpers
                .match_first_type_mut::<QemuSnapshotHelper>()
                .unwrap();
            h.add_mapped(result, a1 as usize, Some(prot));
        }
    } else if i64::from(sys_num) == SYS_mremap {
        let h = helpers
            .match_first_type_mut::<QemuSnapshotHelper>()
            .unwrap();
        h.add_mapped(result, a2 as usize, None);
    } else if i64::from(sys_num) == SYS_mprotect {
        if let Ok(prot) = MmapPerms::try_from(a2 as i32) {
            let h = helpers
                .match_first_type_mut::<QemuSnapshotHelper>()
                .unwrap();
            h.add_mapped(a0, a2 as usize, Some(prot));
        }
    }
    result
}
