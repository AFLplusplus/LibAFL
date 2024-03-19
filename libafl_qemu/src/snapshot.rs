use std::{
    cell::UnsafeCell,
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use libafl::{inputs::UsesInput, state::HasMetadata};
use meminterval::{Interval, IntervalTree};
use thread_local::ThreadLocal;

#[cfg(any(cpu_target = "arm", cpu_target = "i386", cpu_target = "mips"))]
use crate::SYS_fstatat64;
#[cfg(not(cpu_target = "arm"))]
use crate::SYS_mmap;
#[cfg(any(cpu_target = "arm", cpu_target = "mips"))]
use crate::SYS_mmap2;
#[cfg(not(any(
    cpu_target = "arm",
    cpu_target = "mips",
    cpu_target = "i386",
    cpu_target = "ppc"
)))]
use crate::SYS_newfstatat;
use crate::{
    asan::QemuAsanHelper,
    emu::{Emulator, MmapPerms, SyscallHookResult},
    helper::{QemuHelper, QemuHelperTuple},
    hooks::{Hook, QemuHooks},
    GuestAddr, SYS_fstat, SYS_fstatfs, SYS_futex, SYS_getrandom, SYS_mprotect, SYS_mremap,
    SYS_munmap, SYS_pread64, SYS_read, SYS_readlinkat, SYS_statfs,
};

// TODO use the functions provided by Emulator
pub const SNAPSHOT_PAGE_SIZE: usize = 4096;
pub const SNAPSHOT_PAGE_MASK: GuestAddr = !(SNAPSHOT_PAGE_SIZE as GuestAddr - 1);

pub type StopExecutionCallback = Box<dyn FnMut(&mut QemuSnapshotHelper, &Emulator)>;

#[derive(Debug)]
pub struct SnapshotPageInfo {
    pub addr: GuestAddr,
    pub perms: MmapPerms,
    pub private: bool,
    pub data: Option<Box<[u8; SNAPSHOT_PAGE_SIZE]>>,
}

#[derive(Default, Debug)]
pub struct SnapshotAccessInfo {
    pub access_cache: [GuestAddr; 4],
    pub access_cache_idx: usize,
    pub dirty: HashSet<GuestAddr>,
}

impl SnapshotAccessInfo {
    pub fn clear(&mut self) {
        self.access_cache_idx = 0;
        self.access_cache = [GuestAddr::MAX; 4];
        self.dirty.clear();
    }
}

#[derive(Clone, Default, Debug)]
pub struct MemoryRegionInfo {
    pub perms: Option<MmapPerms>,
    pub changed: bool,
}

#[derive(Clone, Default, Debug)]
pub struct MappingInfo {
    pub tree: IntervalTree<GuestAddr, MemoryRegionInfo>,
    pub size: usize,
}

pub struct QemuSnapshotHelper {
    pub accesses: ThreadLocal<UnsafeCell<SnapshotAccessInfo>>,
    pub maps: MappingInfo,
    pub new_maps: Mutex<MappingInfo>,
    pub pages: HashMap<GuestAddr, SnapshotPageInfo>,
    pub brk: GuestAddr,
    pub mmap_start: GuestAddr,
    pub mmap_limit: usize,
    pub stop_execution: Option<StopExecutionCallback>,
    pub empty: bool,
    pub accurate_unmap: bool,
}

impl core::fmt::Debug for QemuSnapshotHelper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QemuSnapshotHelper")
            .field("accesses", &self.accesses)
            .field("new_maps", &self.new_maps)
            .field("pages", &self.pages)
            .field("brk", &self.brk)
            .field("mmap_start", &self.mmap_start)
            .field("mmap_limit", &self.mmap_limit)
            .field("empty", &self.empty)
            .finish_non_exhaustive()
    }
}

impl QemuSnapshotHelper {
    #[must_use]
    pub fn new() -> Self {
        Self {
            accesses: ThreadLocal::new(),
            maps: MappingInfo::default(),
            new_maps: Mutex::new(MappingInfo::default()),
            pages: HashMap::default(),
            brk: 0,
            mmap_start: 0,
            mmap_limit: 0,
            stop_execution: None,
            empty: true,
            accurate_unmap: false,
        }
    }

    #[must_use]
    pub fn with_mmap_limit(mmap_limit: usize, stop_execution: StopExecutionCallback) -> Self {
        Self {
            accesses: ThreadLocal::new(),
            maps: MappingInfo::default(),
            new_maps: Mutex::new(MappingInfo::default()),
            pages: HashMap::default(),
            brk: 0,
            mmap_start: 0,
            mmap_limit,
            stop_execution: Some(stop_execution),
            empty: true,
            accurate_unmap: false,
        }
    }

    pub fn use_accurate_unmapping(&mut self) {
        self.accurate_unmap = true;
    }

    #[allow(clippy::uninit_assumed_init)]
    pub fn snapshot(&mut self, emulator: &Emulator) {
        self.brk = emulator.get_brk();
        self.mmap_start = emulator.get_mmap_start();
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
                if map.flags().is_r() {
                    // TODO not just for R pages
                    unsafe {
                        info.data = Some(Box::new(core::mem::zeroed()));
                        emulator.read_mem(addr, &mut info.data.as_mut().unwrap()[..]);
                    }
                }
                self.pages.insert(addr, info);
                addr += SNAPSHOT_PAGE_SIZE as GuestAddr;
            }

            self.maps.tree.insert(
                map.start()..map.end(),
                MemoryRegionInfo {
                    perms: Some(map.flags()),
                    changed: false,
                },
            );
            self.maps.size += (map.end() - map.start()) as usize;
        }
        self.empty = false;
        *self.new_maps.lock().unwrap() = self.maps.clone();
    }

    pub fn page_access(&mut self, page: GuestAddr) {
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

    pub fn page_access_no_cache(&self, page: GuestAddr) {
        unsafe {
            let acc = self.accesses.get_or_default().get();
            (*acc).dirty.insert(page);
        }
    }

    pub fn access(&mut self, addr: GuestAddr, size: usize) {
        // ASSUMPTION: the access can only cross 2 pages
        debug_assert!(size > 0);
        let page = addr & SNAPSHOT_PAGE_MASK;
        self.page_access(page);
        let second_page = (addr + size as GuestAddr - 1) & SNAPSHOT_PAGE_MASK;
        if page != second_page {
            self.page_access(second_page);
        }
    }

    pub fn reset(&mut self, emulator: &Emulator) {
        {
            let new_maps = self.new_maps.get_mut().unwrap();

            for acc in &mut self.accesses {
                unsafe { &mut (*acc.get()) }.dirty.retain(|page| {
                    if let Some(info) = self.pages.get_mut(page) {
                        // TODO avoid duplicated memcpy
                        if let Some(data) = info.data.as_ref() {
                            // Change segment perms to RW if not writeable in current mapping
                            let mut found = false;
                            for entry in new_maps
                                .tree
                                .query_mut(*page..(page + SNAPSHOT_PAGE_SIZE as GuestAddr))
                            {
                                if !entry.value.perms.unwrap_or(MmapPerms::None).is_w() {
                                    drop(emulator.mprotect(
                                        entry.interval.start,
                                        (entry.interval.end - entry.interval.start) as usize,
                                        MmapPerms::ReadWrite,
                                    ));
                                    entry.value.changed = true;
                                    entry.value.perms = Some(MmapPerms::ReadWrite);
                                }
                                found = true;
                            }

                            if !found {
                                return true; // Restore later
                            }

                            unsafe { emulator.write_mem(*page, &data[..]) };
                        } else {
                            panic!("Cannot restored a dirty but unsaved page");
                        }
                    }
                    false
                });
            }
        }

        self.reset_maps(emulator);

        // This one is after that we remapped potential regions mapped at snapshot time but unmapped during execution
        for acc in &mut self.accesses {
            for page in unsafe { &(*acc.get()).dirty } {
                for entry in self
                    .maps
                    .tree
                    .query_mut(*page..(page + SNAPSHOT_PAGE_SIZE as GuestAddr))
                {
                    if !entry.value.perms.unwrap_or(MmapPerms::None).is_w() && !entry.value.changed
                    {
                        drop(emulator.mprotect(
                            entry.interval.start,
                            (entry.interval.end - entry.interval.start) as usize,
                            MmapPerms::ReadWrite,
                        ));
                        entry.value.changed = true;
                    }
                }

                if let Some(info) = self.pages.get_mut(page) {
                    // TODO avoid duplicated memcpy
                    if let Some(data) = info.data.as_ref() {
                        unsafe { emulator.write_mem(*page, &data[..]) };
                    } else {
                        panic!("Cannot restored a dirty but unsaved page");
                    }
                }
            }
            unsafe { (*acc.get()).clear() };
        }

        for entry in self.maps.tree.query_mut(0..GuestAddr::MAX) {
            if entry.value.changed {
                drop(emulator.mprotect(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                ));
                entry.value.changed = false;
            }
        }

        emulator.set_brk(self.brk);
        emulator.set_mmap_start(self.mmap_start);
    }

    pub fn is_unmap_allowed(&mut self, start: GuestAddr, mut size: usize) -> bool {
        if size % SNAPSHOT_PAGE_SIZE != 0 {
            size = size + (SNAPSHOT_PAGE_SIZE - size % SNAPSHOT_PAGE_SIZE);
        }
        self.maps
            .tree
            .query(start..(start + (size as GuestAddr)))
            .next()
            .is_none()
    }

    pub fn add_mapped(&mut self, start: GuestAddr, mut size: usize, perms: Option<MmapPerms>) {
        if size == 0 {
            return;
        }

        let total_size = {
            if size % SNAPSHOT_PAGE_SIZE != 0 {
                size = size + (SNAPSHOT_PAGE_SIZE - size % SNAPSHOT_PAGE_SIZE);
            }
            let mut mapping = self.new_maps.lock().unwrap();
            mapping.tree.insert(
                start..(start + (size as GuestAddr)),
                MemoryRegionInfo {
                    perms,
                    changed: true,
                },
            );
            mapping.size += size;
            mapping.size
        };

        if self.mmap_limit != 0 && total_size > self.mmap_limit {
            let mut cb = self.stop_execution.take().unwrap();
            let emu = Emulator::get().unwrap();
            (cb)(self, &emu);
            self.stop_execution = Some(cb);
        }
    }

    pub fn change_mapped(&mut self, start: GuestAddr, mut size: usize, perms: Option<MmapPerms>) {
        if size % SNAPSHOT_PAGE_SIZE != 0 {
            size = size + (SNAPSHOT_PAGE_SIZE - size % SNAPSHOT_PAGE_SIZE);
        }
        let mut mapping = self.new_maps.lock().unwrap();

        let interval = Interval::new(start, start + (size as GuestAddr));
        let mut found = vec![]; //  TODO optimize
        for entry in mapping.tree.query(interval) {
            found.push((*entry.interval, entry.value.perms));
        }

        for (i, perms) in found {
            let overlap = i.intersect(&interval).unwrap();

            mapping.tree.delete(i);

            if i.start < overlap.start {
                mapping.tree.insert(
                    i.start..overlap.start,
                    MemoryRegionInfo {
                        perms,
                        changed: true,
                    },
                );
            }
            if i.end > overlap.end {
                mapping.tree.insert(
                    overlap.end..i.end,
                    MemoryRegionInfo {
                        perms,
                        changed: true,
                    },
                );
            }
        }

        mapping.tree.insert(
            interval,
            MemoryRegionInfo {
                perms,
                changed: true,
            },
        );
    }

    pub fn remove_mapped(&mut self, start: GuestAddr, mut size: usize) {
        if size % SNAPSHOT_PAGE_SIZE != 0 {
            size = size + (SNAPSHOT_PAGE_SIZE - size % SNAPSHOT_PAGE_SIZE);
        }

        let mut mapping = self.new_maps.lock().unwrap();

        let interval = Interval::new(start, start + (size as GuestAddr));
        let mut found = vec![]; //  TODO optimize
        for entry in mapping.tree.query(interval) {
            found.push((*entry.interval, entry.value.perms));
        }

        for (i, perms) in found {
            let overlap = i.intersect(&interval).unwrap();

            mapping.tree.delete(i);
            for page in (i.start..i.end).step_by(SNAPSHOT_PAGE_SIZE) {
                self.page_access_no_cache(page);
            }

            if i.start < overlap.start {
                mapping.tree.insert(
                    i.start..overlap.start,
                    MemoryRegionInfo {
                        perms,
                        changed: true,
                    },
                );
            }
            if i.end > overlap.end {
                mapping.tree.insert(
                    overlap.end..i.end,
                    MemoryRegionInfo {
                        perms,
                        changed: true,
                    },
                );
            }
        }
    }

    pub fn reset_maps(&mut self, emulator: &Emulator) {
        let new_maps = self.new_maps.get_mut().unwrap();

        for entry in self.maps.tree.query(0..GuestAddr::MAX) {
            let mut found = vec![]; //  TODO optimize
            for overlap in new_maps.tree.query(*entry.interval) {
                found.push((
                    *overlap.interval,
                    overlap.value.changed,
                    overlap.value.perms,
                ));
            }

            if found.is_empty() {
                //panic!("A pre-snapshot memory region was unmapped");
                drop(emulator.map_fixed(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                ));
            } else if found.len() == 1 && found[0].0 == *entry.interval {
                if found[0].1 && found[0].2 != entry.value.perms {
                    drop(emulator.mprotect(
                        entry.interval.start,
                        (entry.interval.end - entry.interval.start) as usize,
                        entry.value.perms.unwrap(),
                    ));
                }
            } else {
                //  TODO check for holes
                drop(emulator.mprotect(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                ));
            }

            for (i, ..) in found {
                new_maps.tree.delete(i);
            }
        }

        for entry in new_maps.tree.query(0..GuestAddr::MAX) {
            drop(emulator.unmap(
                entry.interval.start,
                (entry.interval.end - entry.interval.start) as usize,
            ));
        }

        *new_maps = self.maps.clone();
    }
}

impl Default for QemuSnapshotHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> QemuHelper<S> for QemuSnapshotHelper
where
    S: UsesInput + HasMetadata,
{
    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        if hooks.match_helper::<QemuAsanHelper>().is_none() {
            // The ASan helper, if present, will call the tracer hook for the snapshot helper as opt
            hooks.writes(
                Hook::Empty,
                Hook::Function(trace_write1_snapshot::<QT, S>),
                Hook::Function(trace_write2_snapshot::<QT, S>),
                Hook::Function(trace_write4_snapshot::<QT, S>),
                Hook::Function(trace_write8_snapshot::<QT, S>),
                Hook::Function(trace_write_n_snapshot::<QT, S>),
            );
        }

        if !self.accurate_unmap {
            hooks.syscalls(Hook::Function(filter_mmap_snapshot::<QT, S>));
        }
        hooks.after_syscalls(Hook::Function(trace_mmap_snapshot::<QT, S>));
    }

    fn pre_exec(&mut self, emulator: &Emulator, _input: &S::Input) {
        if self.empty {
            self.snapshot(emulator);
        } else {
            self.reset(emulator);
        }
    }
}

pub fn trace_write1_snapshot<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
    h.access(addr, 1);
}

pub fn trace_write2_snapshot<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
    h.access(addr, 2);
}

pub fn trace_write4_snapshot<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
    h.access(addr, 4);
}

pub fn trace_write8_snapshot<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
    h.access(addr, 8);
}

pub fn trace_write_n_snapshot<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
    size: usize,
) where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
    h.access(addr, size);
}

#[allow(clippy::too_many_arguments)]
#[allow(non_upper_case_globals)]
pub fn filter_mmap_snapshot<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    sys_num: i32,
    a0: GuestAddr,
    a1: GuestAddr,
    _a2: GuestAddr,
    _a3: GuestAddr,
    _a4: GuestAddr,
    _a5: GuestAddr,
    _a6: GuestAddr,
    _a7: GuestAddr,
) -> SyscallHookResult
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    if i64::from(sys_num) == SYS_munmap {
        let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
        if !h.is_unmap_allowed(a0 as GuestAddr, a1 as usize) {
            return SyscallHookResult::new(Some(0));
        }
    }
    SyscallHookResult::new(None)
}

#[allow(clippy::too_many_arguments)]
#[allow(non_upper_case_globals)]
pub fn trace_mmap_snapshot<QT, S>(
    hooks: &mut QemuHooks<QT, S>,
    _state: Option<&mut S>,
    result: GuestAddr,
    sys_num: i32,
    a0: GuestAddr,
    a1: GuestAddr,
    a2: GuestAddr,
    a3: GuestAddr,
    _a4: GuestAddr,
    _a5: GuestAddr,
    _a6: GuestAddr,
    _a7: GuestAddr,
) -> GuestAddr
where
    S: UsesInput,
    QT: QemuHelperTuple<S>,
{
    // NOT A COMPLETE LIST OF MEMORY EFFECTS
    match i64::from(sys_num) {
        SYS_read | SYS_pread64 => {
            let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
            h.access(a1, a2 as usize);
        }
        SYS_readlinkat => {
            let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
            h.access(a2, a3 as usize);
        }
        SYS_futex => {
            let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
            h.access(a0, a3 as usize);
        }
        #[cfg(not(any(
            cpu_target = "arm",
            cpu_target = "i386",
            cpu_target = "mips",
            cpu_target = "ppc"
        )))]
        SYS_newfstatat => {
            if a2 != 0 {
                let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
                h.access(a2, 4096); // stat is not greater than a page
            }
        }
        #[cfg(any(cpu_target = "arm", cpu_target = "mips", cpu_target = "i386"))]
        SYS_fstatat64 => {
            if a2 != 0 {
                let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
                h.access(a2, 4096); // stat is not greater than a page
            }
        }
        SYS_statfs | SYS_fstatfs | SYS_fstat => {
            let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
            h.access(a1, 4096); // stat is not greater than a page
        }
        SYS_getrandom => {
            let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
            h.access(a0, a1 as usize);
        }
        // mmap syscalls
        sys_const => {
            if result == GuestAddr::MAX
            /* -1 */
            {
                return result;
            }

            // TODO handle huge pages

            #[cfg(any(cpu_target = "arm", cpu_target = "mips"))]
            if sys_const == SYS_mmap2 {
                if let Ok(prot) = MmapPerms::try_from(a2 as i32) {
                    let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
                    h.add_mapped(result, a1 as usize, Some(prot));
                }
            }

            #[cfg(not(cpu_target = "arm"))]
            if sys_const == SYS_mmap {
                if let Ok(prot) = MmapPerms::try_from(a2 as i32) {
                    let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
                    h.add_mapped(result, a1 as usize, Some(prot));
                }
            }

            if sys_const == SYS_mremap {
                let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
                // TODO get the old permissions from the removed mapping
                h.remove_mapped(a0, a1 as usize);
                h.add_mapped(result, a2 as usize, None);
            } else if sys_const == SYS_mprotect {
                if let Ok(prot) = MmapPerms::try_from(a2 as i32) {
                    let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
                    h.add_mapped(a0, a1 as usize, Some(prot));
                }
            } else if sys_const == SYS_munmap {
                let h = hooks.match_helper_mut::<QemuSnapshotHelper>().unwrap();
                if !h.accurate_unmap && !h.is_unmap_allowed(a0, a1 as usize) {
                    h.remove_mapped(a0, a1 as usize);
                }
            }
        }
    }
    result
}
