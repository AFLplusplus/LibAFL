#![allow(clippy::needless_pass_by_value)] // default compiler complains about Option<&mut T> otherwise, and this is used extensively.
use std::{cell::UnsafeCell, mem::MaybeUninit, ops::Range, sync::Mutex};

use hashbrown::{HashMap, HashSet};
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
    Qemu, SYS_brk, SYS_mprotect, SYS_mremap, SYS_munmap, SYS_pread64, SYS_read, SYS_readlinkat,
    emu::EmulatorModules,
    modules::{
        EmulatorModule, EmulatorModuleTuple,
        asan::AsanModule,
        utils::filters::{HasAddressFilter, NOP_ADDRESS_FILTER, NopAddressFilter},
    },
    qemu::{Hook, SyscallHookResult},
};
#[cfg(not(cpu_target = "riscv32"))]
use crate::{SYS_fstat, SYS_fstatfs, SYS_futex, SYS_getrandom, SYS_statfs};

// TODO use the functions provided by Qemu
pub const SNAPSHOT_PAGE_SIZE: usize = 4096;
pub const SNAPSHOT_PAGE_ZEROES: [u8; SNAPSHOT_PAGE_SIZE] = [0; SNAPSHOT_PAGE_SIZE];
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
#[derive(Clone, Debug)]
pub enum IntervalSnapshotFilter {
    All,
    AllowList(Vec<Range<GuestAddr>>),
    DenyList(Vec<Range<GuestAddr>>),
    ZeroList(Vec<Range<GuestAddr>>),
}

#[derive(Clone, Default, Debug)]
pub struct IntervalSnapshotFilters {
    filters: Vec<IntervalSnapshotFilter>,
}

impl From<Vec<IntervalSnapshotFilter>> for IntervalSnapshotFilters {
    fn from(filters: Vec<IntervalSnapshotFilter>) -> Self {
        Self { filters }
    }
}

impl IntervalSnapshotFilters {
    #[must_use]
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    #[must_use]
    pub fn to_skip(&self, addr: GuestAddr) -> Option<&Range<GuestAddr>> {
        for filter in &self.filters {
            match filter {
                IntervalSnapshotFilter::All => return None,
                IntervalSnapshotFilter::AllowList(allow_list) => {
                    if allow_list.iter().any(|range| range.contains(&addr)) {
                        return None;
                    }
                }
                IntervalSnapshotFilter::DenyList(deny_list) => {
                    let deny = deny_list.iter().find(|range| range.contains(&addr));
                    if deny.is_some() {
                        return deny;
                    }
                }
                IntervalSnapshotFilter::ZeroList(_) => {}
            }
        }
        None
    }

    #[must_use]
    pub fn to_zero(&self, addr: GuestAddr) -> Option<&Range<GuestAddr>> {
        for filter in &self.filters {
            if let IntervalSnapshotFilter::ZeroList(zero_list) = filter {
                let zero = zero_list.iter().find(|range| range.contains(&addr));
                if zero.is_some() {
                    return zero;
                }
            }
        }
        None
    }
}

pub struct SnapshotModule {
    pub accesses: ThreadLocal<UnsafeCell<SnapshotAccessInfo>>,
    pub maps: MappingInfo,
    pub new_maps: Mutex<MappingInfo>,
    pub pages: HashMap<GuestAddr, SnapshotPageInfo>,
    pub initial_brk: GuestAddr,
    pub brk: GuestAddr,
    pub mmap_start: GuestAddr,
    pub mmap_limit: usize,
    pub stop_execution: Option<StopExecutionCallback>,
    pub empty: bool,
    pub interval_filter: IntervalSnapshotFilters,
    auto_reset: bool,
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
            initial_brk: 0,
            brk: 0,
            mmap_start: 0,
            mmap_limit: 0,
            stop_execution: None,
            empty: true,
            interval_filter: IntervalSnapshotFilters::new(),
            auto_reset: true,
        }
    }

    #[must_use]
    pub fn with_filters(interval_filter: IntervalSnapshotFilters) -> Self {
        Self {
            accesses: ThreadLocal::new(),
            maps: MappingInfo::default(),
            new_maps: Mutex::new(MappingInfo::default()),
            pages: HashMap::default(),
            initial_brk: 0,
            brk: 0,
            mmap_start: 0,
            mmap_limit: 0,
            stop_execution: None,
            empty: true,
            interval_filter,
            auto_reset: true,
        }
    }

    #[must_use]
    pub fn with_mmap_limit(mmap_limit: usize, stop_execution: StopExecutionCallback) -> Self {
        Self {
            accesses: ThreadLocal::new(),
            maps: MappingInfo::default(),
            new_maps: Mutex::new(MappingInfo::default()),
            pages: HashMap::default(),
            initial_brk: 0,
            brk: 0,
            mmap_start: 0,
            mmap_limit,
            stop_execution: Some(stop_execution),
            empty: true,
            interval_filter: IntervalSnapshotFilters::new(),
            auto_reset: true,
        }
    }

    pub fn use_manual_reset(&mut self) {
        self.auto_reset = false;
    }

    pub fn snapshot(&mut self, qemu: Qemu) {
        log::info!("Start snapshot");
        self.brk = qemu.get_brk();
        self.initial_brk = qemu.get_initial_brk();
        self.mmap_start = qemu.get_mmap_start();
        self.pages.clear();
        for map in qemu.mappings() {
            let mut addr = map.start();
            while addr < map.end() {
                let zero = self.interval_filter.to_zero(addr);
                let skip = self.interval_filter.to_skip(addr);
                if let Some(range) = zero.or(skip) {
                    addr = range.end;
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
        debug_assert!(size <= SNAPSHOT_PAGE_SIZE);
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
                let zero = self.interval_filter.to_zero(addr);
                let skip = self.interval_filter.to_skip(addr);
                if let Some(range) = zero.or(skip) {
                    addr = range.end;
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
                    log::warn!("\tpage not found @addr 0x{addr:x}");
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

            let new_brk = qemu.get_brk();
            if new_brk < self.brk {
                // The heap has shrunk below the snapshotted brk value. We need to remap those pages in the target.
                // The next for loop will restore their content if needed.
                let aligned_new_brk = (new_brk + ((SNAPSHOT_PAGE_SIZE - 1) as GuestAddr))
                    & (!(SNAPSHOT_PAGE_SIZE - 1) as GuestAddr);
                log::debug!(
                    "New brk ({:#x?}) < snapshotted brk ({:#x?})! Mapping back in the target {:#x?} - {:#x?}",
                    new_brk,
                    self.brk,
                    aligned_new_brk,
                    aligned_new_brk + (self.brk - aligned_new_brk)
                );
                qemu.map_fixed(
                    aligned_new_brk,
                    (self.brk - aligned_new_brk) as usize,
                    MmapPerms::ReadWrite,
                )
                .unwrap();
            } else if new_brk > self.brk {
                // The heap has grown. so we want to drop those
                // we want to align the addresses before calling unmap
                // although it is very unlikely that the brk has an unaligned value
                let new_page_boundary = (new_brk + ((SNAPSHOT_PAGE_SIZE - 1) as GuestAddr))
                    & (!(SNAPSHOT_PAGE_SIZE - 1) as GuestAddr);
                let old_page_boundary = (self.brk + ((SNAPSHOT_PAGE_SIZE - 1) as GuestAddr))
                    & (!(SNAPSHOT_PAGE_SIZE - 1) as GuestAddr);

                if new_page_boundary != old_page_boundary {
                    let unmap_sz = (new_page_boundary - old_page_boundary) as usize;
                    // if self.brk is not aligned this call will return an error
                    // and it will page align this unmap_sz too (but it is already aligned for us)
                    // look at target_munmap in qemu-libafl-bridge
                    qemu.unmap(self.brk, unmap_sz).unwrap();
                }
            }

            for acc in &mut self.accesses {
                unsafe { &mut (*acc.get()) }.dirty.retain(|page| {
                    if let Some(info) = self.pages.get_mut(page) {
                        if self.interval_filter.to_skip(*page).is_some() {
                            if !Self::modify_mapping(qemu, new_maps, *page) {
                                return true; // Restore later
                            }
                            unsafe { qemu.write_mem_unchecked(*page, &SNAPSHOT_PAGE_ZEROES) };
                        } else if let Some(data) = info.data.as_ref() {
                            // TODO avoid duplicated memcpy
                            // Change segment perms to RW if not writeable in current mapping
                            if !Self::modify_mapping(qemu, new_maps, *page) {
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
                        qemu.mprotect(
                            entry.interval.start,
                            (entry.interval.end - entry.interval.start) as usize,
                            MmapPerms::ReadWrite,
                        )
                        .unwrap();
                        entry.value.changed = true;
                    }
                }

                if self.interval_filter.to_skip(*page).is_some() {
                    unsafe { qemu.write_mem_unchecked(*page, &SNAPSHOT_PAGE_ZEROES) };
                } else if let Some(info) = self.pages.get_mut(page) {
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
                qemu.mprotect(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                )
                .unwrap();
                entry.value.changed = false;
            }
        }

        qemu.set_brk(self.brk);
        qemu.set_mmap_start(self.mmap_start);

        #[cfg(feature = "paranoid_debug")]
        self.check_snapshot(qemu);

        log::debug!("End restore");
    }

    fn modify_mapping(qemu: Qemu, maps: &mut MappingInfo, page: GuestAddr) -> bool {
        let mut found = false;
        for entry in maps
            .tree
            .query_mut(page..(page + SNAPSHOT_PAGE_SIZE as GuestAddr))
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
        found
    }

    /// Unmap is allowed if it is not part of the pre-snapshot region. maybe check if it's part
    /// of qemu's guest memory or not?
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

    pub fn change_mapped_perms(
        &mut self,
        start: GuestAddr,
        mut size: usize,
        perms: Option<MmapPerms>,
    ) {
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
                qemu.map_fixed(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                )
                .unwrap();
            } else if found.len() == 1 && found[0].0 == *entry.interval {
                if found[0].1 && found[0].2 != entry.value.perms {
                    qemu.mprotect(
                        entry.interval.start,
                        (entry.interval.end - entry.interval.start) as usize,
                        entry.value.perms.unwrap(),
                    )
                    .unwrap();
                }
            } else {
                //  TODO check for holes
                qemu.mprotect(
                    entry.interval.start,
                    (entry.interval.end - entry.interval.start) as usize,
                    entry.value.perms.unwrap(),
                )
                .unwrap();
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
            qemu.unmap(i.start, (i.end - i.start) as usize).unwrap();
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

impl<I, S> EmulatorModule<I, S> for SnapshotModule
where
    I: Unpin,
    S: Unpin,
{
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        if emulator_modules.get::<AsanModule>().is_none() {
            // The ASan module, if present, will call the tracer hook for the snapshot helper as opt
            emulator_modules.writes(
                Hook::Empty,
                Hook::Function(trace_write_snapshot::<ET, I, S, 1>),
                Hook::Function(trace_write_snapshot::<ET, I, S, 2>),
                Hook::Function(trace_write_snapshot::<ET, I, S, 4>),
                Hook::Function(trace_write_snapshot::<ET, I, S, 8>),
                Hook::Function(trace_write_n_snapshot::<ET, I, S>),
            );
        }

        emulator_modules.pre_syscalls(Hook::Function(filter_mmap_snapshot::<ET, I, S>));

        emulator_modules.post_syscalls(Hook::Function(trace_mmap_snapshot::<ET, I, S>));
    }

    fn pre_exec<ET>(
        &mut self,
        qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        _input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        if self.empty {
            self.snapshot(qemu);
        } else if self.auto_reset {
            self.reset(qemu);
        }
    }
}

impl HasAddressFilter for SnapshotModule {
    type AddressFilter = NopAddressFilter;
    fn address_filter(&self) -> &Self::AddressFilter {
        &NopAddressFilter
    }

    fn address_filter_mut(&mut self) -> &mut Self::AddressFilter {
        unsafe { (&raw mut NOP_ADDRESS_FILTER).as_mut().unwrap().get_mut() }
    }
}

pub fn trace_write_snapshot<ET, I, S, const SIZE: usize>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
    h.access(addr, SIZE);
}

pub fn trace_write_n_snapshot<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    _id: u64,
    _pc: GuestAddr,
    addr: GuestAddr,
    size: usize,
) where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
    h.access(addr, size);
}

/// Do not consider munmap syscalls that are not allowed
#[expect(clippy::too_many_arguments)]
pub fn filter_mmap_snapshot<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
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
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    if i64::from(sys_num) == SYS_munmap {
        let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
        if !h.is_unmap_allowed(a0 as GuestAddr, a1 as usize) {
            return SyscallHookResult::new(Some(0));
        }
    }

    SyscallHookResult::new(None)
}

#[expect(non_upper_case_globals, clippy::too_many_arguments)]
pub fn trace_mmap_snapshot<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
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
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
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
            // We don't handle brk here. It is handled in the reset function only when it's needed.
            log::debug!("New brk ({result:#x?}) received.");
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
                    h.change_mapped_perms(a0, a1 as usize, Some(prot));
                }
            } else if sys_const == SYS_munmap {
                let h = emulator_modules.get_mut::<SnapshotModule>().unwrap();
                if h.is_unmap_allowed(a0, a1 as usize) {
                    h.remove_mapped(a0, a1 as usize);
                }
            }
        }
    }
    result
}
