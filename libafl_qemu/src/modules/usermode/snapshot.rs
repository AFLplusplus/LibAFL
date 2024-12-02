use std::{cell::UnsafeCell, mem::MaybeUninit, sync::Mutex};

use hashbrown::{HashMap, HashSet};
use libafl::inputs::UsesInput;
use libafl_qemu_sys::{GuestAddr, MmapPerms};
use meminterval::{Interval, IntervalTree};
use thread_local::ThreadLocal;

#[cfg(any(cpu_target = "arm", cpu_target = "i386", cpu_target = "mips"))]
use crate::SYS_fstatat64;
#[cfg(not(any(cpu_target = "arm", cpu_target = "riscv32")))]
use crate::SYS_mmap;
#[cfg(any(cpu_target = "arm", cpu_target = "mips", cpu_target = "riscv32"))]
use crate::SYS_mmap2;
#[cfg(not(any(
    cpu_target = "arm",
    cpu_target = "mips",
    cpu_target = "i386",
    cpu_target = "ppc",
    cpu_target = "riscv32",
)))]
use crate::SYS_newfstatat;
use crate::{
    emu::EmulatorModules,
    modules::{
        asan::AsanModule, EmulatorModule, EmulatorModuleTuple, NopAddressFilter, Range,
        NOP_ADDRESS_FILTER,
    },
    qemu::{Hook, SyscallHookResult},
    Qemu, SYS_brk, SYS_mprotect, SYS_mremap, SYS_munmap, SYS_pread64, SYS_read, SYS_readlinkat,
};
#[cfg(not(cpu_target = "riscv32"))]
use crate::{SYS_fstat, SYS_fstatfs, SYS_futex, SYS_getrandom, SYS_statfs};

// TODO use the functions provided by Qemu
pub const SNAPSHOT_PAGE_SIZE: usize = 4096;
pub const SNAPSHOT_PAGE_MASK: GuestAddr = !(SNAPSHOT_PAGE_SIZE as GuestAddr - 1);

pub type StopExecutionCallback = Box<dyn FnMut(&mut SnapshotModule, Qemu)>;

#[derive(Clone, Debug)]
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

/// Filter used to select which pages should be snapshotted or not.
///
/// It is supposed to be used primarily for debugging, its usage is discouraged.
/// If you end up needing it, you most likely have an issue with the snapshot system.
/// If this is the case, please [fill in an issue on the main repository](https://github.com/AFLplusplus/LibAFL/issues).
pub enum IntervalSnapshotFilter {
    All,
    AllowList(Vec<Range<GuestAddr>>),
    DenyList(Vec<Range<GuestAddr>>),
}

pub struct SnapshotModule {
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
    pub interval_filter: Vec<IntervalSnapshotFilter>,
}

impl core::fmt::Debug for SnapshotModule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotModule")
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

impl SnapshotModule {
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
            interval_filter: Vec::<IntervalSnapshotFilter>::new(),
        }
    }

    #[must_use]
    pub fn with_filters(interval_filter: Vec<IntervalSnapshotFilter>) -> Self {
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
            interval_filter,
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
            interval_filter: Vec::<IntervalSnapshotFilter>::new(),
        }
    }

    pub fn use_accurate_unmapping(&mut self) {
        self.accurate_unmap = true;
    }

    pub fn to_skip(&self, addr: GuestAddr) -> bool {
        for filter in &self.interval_filter {
            match filter {
                IntervalSnapshotFilter::All => return false,
                IntervalSnapshotFilter::AllowList(allow_list) => {
                    if allow_list.iter().any(|range| range.contains(&addr)) {
                        return false;
                    }
                }
                IntervalSnapshotFilter::DenyList(deny_list) => {
                    if deny_list.iter().any(|range| range.contains(&addr)) {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[allow(clippy::uninit_assumed_init)]
    pub fn snapshot(&mut self, qemu: Qemu) {
        log::info!("Start snapshot");
        self.brk = qemu.get_brk();
        self.mmap_start = qemu.get_mmap_start();
        self.pages.clear();
        for map in qemu.mappings() {
            let mut addr = map.start();
            while addr < map.end() {
                if self.to_skip(addr) {
                    addr += SNAPSHOT_PAGE_SIZE as GuestAddr;
                    continue;
                }
                let mut info = SnapshotPageInfo {
                    addr,
                    perms: map.flags(),
                    private: map.is_priv(),
                    data: None,
                };
                if map.flags().readable() {
                    // TODO not just for R pages
                    unsafe {
                        info.data = Some(Box::new(core::mem::zeroed()));
                        qemu.read_mem_unchecked(addr, &mut info.data.as_mut().unwrap()[..]);
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
        log::info!("End snapshot");
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
        debug_assert!(size > 0 && size <= SNAPSHOT_PAGE_SIZE);
        let page = addr & SNAPSHOT_PAGE_MASK;
        self.page_access(page);
        let second_page = (addr + size as GuestAddr - 1) & SNAPSHOT_PAGE_MASK;
        if page != second_page {
            self.page_access(second_page);
        }
    }

    pub fn check_snapshot(&self, qemu: Qemu) {
        let mut saved_pages_list = self.pages.clone();

        log::info!("Checking snapshot correctness");

        let mut perm_errors: Vec<(GuestAddr, MmapPerms, MmapPerms)> = Vec::new();
        let mut content_mismatch = false;

        for map in qemu.mappings() {
            let mut addr = map.start();
            // assert_eq!(addr & SNAPSHOT_PAGE_MASK, 0);
            while addr < map.end() {
                if self.to_skip(addr) {
                    addr += SNAPSHOT_PAGE_SIZE as GuestAddr;
                    continue;
                }
                if let Some(saved_page) = saved_pages_list.remove(&addr) {
                    if saved_page.perms.readable() {
                        let mut current_page_content: MaybeUninit<[u8; SNAPSHOT_PAGE_SIZE]> =
                            MaybeUninit::uninit();

                        if saved_page.perms != map.flags() {
                            perm_errors.push((addr, saved_page.perms, map.flags()));
                            log::warn!(
                                "\t0x{:x}: Flags do not match: saved is {:?} and current is {:?}",
                                addr,
                                saved_page.perms,
                                map.flags()
                            );
                        }

                        unsafe {
                            qemu.read_mem(
                                addr,
                                current_page_content.as_mut_ptr().as_mut().unwrap(),
                            )
                            .unwrap();
                        }

                        let current_page_content: &mut [u8; SNAPSHOT_PAGE_SIZE] =
                            unsafe { &mut current_page_content.assume_init() };

                        if saved_page.data.as_ref().unwrap().as_ref()
                            != current_page_content.as_ref()
                        {
                            let mut offsets = Vec::new();
                            for (i, (saved_page_byte, current_page_byte)) in saved_page
                                .data
                                .unwrap()
                                .iter()
                                .zip(current_page_content.iter())
                                .enumerate()
                            {
                                if saved_page_byte != current_page_byte {
                                    offsets.push(i);
                                }
                            }
                            log::warn!(
                                "Faulty restore at {}",
                                offsets.iter().fold(String::new(), |acc, offset| format!(
                                    "{}, 0x{:x}",
                                    acc,
                                    addr + *offset as GuestAddr
                                ))
                            );
                            content_mismatch = true;
                        }
                    }
                } else {
                    log::warn!("\tpage not found @addr 0x{:x}", addr);
                }

                addr += SNAPSHOT_PAGE_SIZE as GuestAddr;
            }
        }

        assert!(saved_pages_list.is_empty());

        if !perm_errors.is_empty() {
            let mut perm_error_ranges: Vec<(GuestAddr, GuestAddr, MmapPerms, MmapPerms)> =
                Vec::new();

            for error in perm_errors {
                if let Some(last_range) = perm_error_ranges.last_mut() {
                    if last_range.1 + SNAPSHOT_PAGE_SIZE as GuestAddr == error.0 as GuestAddr
                        && error.1 == last_range.2
                        && error.2 == last_range.3
                    {
                        last_range.1 += SNAPSHOT_PAGE_SIZE as GuestAddr;
                    } else {
                        perm_error_ranges.push((error.0, error.0, error.1, error.2));
                    }
                } else {
                    perm_error_ranges.push((error.0, error.0, error.1, error.2));
                }
            }

            for error_range in perm_error_ranges {
                log::error!(
                    "0x{:x} -> 0x{:x}: saved is {:?} but current is {:?}",
                    error_range.0,
                    error_range.1,
                    error_range.2,
                    error_range.3
                );
            }

            content_mismatch = true;
        }

        assert!(!content_mismatch, "Error found, stopping...");

        log::info!("Snapshot check OK");
    }

    pub fn reset(&mut self, qemu: Qemu) {
        {
            let new_maps = self.new_maps.get_mut().unwrap();

            log::debug!("Start restore");

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
                                if !entry.value.perms.unwrap_or(MmapPerms::None).writable() {
                                    drop(qemu.mprotect(
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

                            unsafe { qemu.write_mem_unchecked(*page, &data[..]) };
                        } else {
                            panic!("Cannot restored a dirty but unsaved page");
                        }
                    }
                    false
                });
            }
        }

        self.reset_maps(qemu);

        // This one is after that we remapped potential regions mapped at snapshot time but unmapped during execution
        for acc in &mut self.accesses {
            for page in unsafe { &(*acc.get()).dirty } {
                for entry in self
                    .maps
                    .tree
                    .query_mut(*page..(page + SNAPSHOT_PAGE_SIZE as GuestAddr))
                {
                    if !entry.value.perms.unwrap_or(MmapPerms::None).writable()
                        && !entry.value.changed
                    {
                        drop(qemu.mprotect(
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
                        unsafe { qemu.write_mem_unchecked(*page, &data[..]) };
                    } else {
                        panic!("Cannot restored a dirty but unsaved page");
                    }
                }
            }
            unsafe { (*acc.get()).clear() };
        }

        for entry in self.maps.tree.query_mut(0..GuestAddr::MAX) {
            if entry.value.changed {
                drop(qemu.mprotect(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                ));
                entry.value.changed = false;
            }
        }

        qemu.set_brk(self.brk);
        qemu.set_mmap_start(self.mmap_start);

        #[cfg(feature = "paranoid_debug")]
        self.check_snapshot(qemu);

        log::debug!("End restore");
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
            let qemu = Qemu::get().unwrap();
            cb(self, qemu);
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

    pub fn reset_maps(&mut self, qemu: Qemu) {
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
                drop(qemu.map_fixed(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                ));
            } else if found.len() == 1 && found[0].0 == *entry.interval {
                if found[0].1 && found[0].2 != entry.value.perms {
                    drop(qemu.mprotect(
                        entry.interval.start,
                        (entry.interval.end - entry.interval.start) as usize,
                        entry.value.perms.unwrap(),
                    ));
                }
            } else {
                //  TODO check for holes
                drop(qemu.mprotect(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                ));
            }

            for (interval, ..) in found {
                new_maps.tree.delete(interval);
            }
        }

        let mut to_unmap = vec![];
        for entry in new_maps.tree.query(0..GuestAddr::MAX) {
            to_unmap.push((*entry.interval, entry.value.changed, entry.value.perms));
        }
        for (i, ..) in to_unmap {
            drop(qemu.unmap(i.start, (i.end - i.start) as usize));
            new_maps.tree.delete(i);
        }

        new_maps.tree.clear();
        new_maps.tree = self.maps.tree.clone();
        new_maps.size = self.maps.size;
    }
}

impl Default for SnapshotModule {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> EmulatorModule<S> for SnapshotModule
where
    S: Unpin + UsesInput,
{
    type ModuleAddressFilter = NopAddressFilter;

    fn post_qemu_init<ET>(&self, emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
        if emulator_modules.get::<AsanModule>().is_none() {
            // The ASan module, if present, will call the tracer hook for the snapshot helper as opt
            emulator_modules.writes(
                Hook::Empty,
                Hook::Function(trace_write_snapshot::<ET, S, 1>),
                Hook::Function(trace_write_snapshot::<ET, S, 2>),
                Hook::Function(trace_write_snapshot::<ET, S, 4>),
                Hook::Function(trace_write_snapshot::<ET, S, 8>),
                Hook::Function(trace_write_n_snapshot::<ET, S>),
            );
        }

        if !self.accurate_unmap {
            emulator_modules.syscalls(Hook::Function(filter_mmap_snapshot::<ET, S>));
        }
        emulator_modules.after_syscalls(Hook::Function(trace_mmap_snapshot::<ET, S>));
    }

    fn pre_exec<ET>(
        &mut self,
        emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        if self.empty {
            self.snapshot(emulator_modules.qemu());
        } else {
            self.reset(emulator_modules.qemu());
        }
    }

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &NopAddressFilter
    }

    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        unsafe { (&raw mut NOP_ADDRESS_FILTER).as_mut().unwrap().get_mut() }
    }
}

pub fn trace_write_snapshot<ET, S, const SIZE: usize>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
) where
    S: Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
    h.access(addr, SIZE);
}

pub fn trace_write_n_snapshot<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
    size: usize,
) where
    S: Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
    h.access(addr, size);
}

#[allow(clippy::too_many_arguments)]
#[allow(non_upper_case_globals)]
pub fn filter_mmap_snapshot<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
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
    S: Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    if i64::from(sys_num) == SYS_munmap {
        let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
        if !h.is_unmap_allowed(a0 as GuestAddr, a1 as usize) {
            return SyscallHookResult::new(Some(0));
        }
    }
    SyscallHookResult::new(None)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
#[allow(non_upper_case_globals)]
pub fn trace_mmap_snapshot<ET, S>(
    emulator_modules: &mut EmulatorModules<ET, S>,
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
    S: Unpin + UsesInput,
    ET: EmulatorModuleTuple<S>,
{
    // NOT A COMPLETE LIST OF MEMORY EFFECTS
    match i64::from(sys_num) {
        SYS_read | SYS_pread64 => {
            let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
            h.access(a1, a2 as usize);
        }
        SYS_readlinkat => {
            let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
            h.access(a2, a3 as usize);
        }
        #[cfg(not(cpu_target = "riscv32"))]
        SYS_futex => {
            let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
            h.access(a0, a3 as usize);
        }
        #[cfg(not(any(
            cpu_target = "arm",
            cpu_target = "i386",
            cpu_target = "mips",
            cpu_target = "ppc",
            cpu_target = "riscv32"
        )))]
        SYS_newfstatat => {
            if a2 != 0 {
                let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
                h.access(a2, 4096); // stat is not greater than a page
            }
        }
        #[cfg(any(cpu_target = "arm", cpu_target = "mips", cpu_target = "i386"))]
        SYS_fstatat64 => {
            if a2 != 0 {
                let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
                h.access(a2, 4096); // stat is not greater than a page
            }
        }
        #[cfg(not(cpu_target = "riscv32"))]
        SYS_statfs | SYS_fstat | SYS_fstatfs => {
            let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
            h.access(a1, 4096); // stat is not greater than a page
        }
        #[cfg(not(cpu_target = "riscv32"))]
        SYS_getrandom => {
            let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
            h.access(a0, a1 as usize);
        }
        SYS_brk => {
            let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
            if h.brk != result && result != 0 {
                /* brk has changed. we change mapping from the snapshotted brk address to the new target_brk
                 * If no brk mapping has been made until now, change_mapped won't change anything and just create a new mapping.
                 * It is safe to assume RW perms here
                 */
                h.change_mapped(h.brk, (result - h.brk) as usize, Some(MmapPerms::ReadWrite));
            }
        }
        // mmap syscalls
        sys_const => {
            if result == GuestAddr::MAX
            /* -1 */
            {
                return result;
            }

            // TODO handle huge pages

            #[cfg(any(cpu_target = "arm", cpu_target = "mips", cpu_target = "riscv32"))]
            if sys_const == SYS_mmap2 {
                if let Ok(prot) = MmapPerms::try_from(a2 as i32) {
                    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
                    h.add_mapped(result, a1 as usize, Some(prot));
                }
            }

            #[cfg(not(any(cpu_target = "arm", cpu_target = "riscv32")))]
            if sys_const == SYS_mmap {
                if let Ok(prot) = MmapPerms::try_from(a2 as i32) {
                    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
                    h.add_mapped(result, a1 as usize, Some(prot));
                }
            }

            if sys_const == SYS_mremap {
                let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
                // TODO get the old permissions from the removed mapping
                h.remove_mapped(a0, a1 as usize);
                h.add_mapped(result, a2 as usize, None);
            } else if sys_const == SYS_mprotect {
                if let Ok(prot) = MmapPerms::try_from(a2 as i32) {
                    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
                    h.change_mapped(a0, a1 as usize, Some(prot));
                }
            } else if sys_const == SYS_munmap {
                let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
                if !h.accurate_unmap && !h.is_unmap_allowed(a0, a1 as usize) {
                    h.remove_mapped(a0, a1 as usize);
                }
            }
        }
    }
    result
}
