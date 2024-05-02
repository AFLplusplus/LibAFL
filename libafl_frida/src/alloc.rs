#[cfg(any(
    windows,
    target_os = "linux",
    target_vendor = "apple",
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_os = "android"
    )
))]
use std::{collections::BTreeMap, ffi::c_void};

use backtrace::Backtrace;
use frida_gum::{PageProtection, RangeDetails};
use hashbrown::HashMap;
use libafl_bolts::cli::FuzzerOptions;
#[cfg(any(
    windows,
    target_os = "linux",
    target_vendor = "apple",
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_os = "android"
    )
))]
use mmap_rs::{MmapFlags, MmapMut, MmapOptions, ReservedMut};
use rangemap::RangeSet;
use serde::{Deserialize, Serialize};

use crate::asan::errors::{AsanError, AsanErrors};

/// An allocator wrapper with binary-only address sanitization
#[derive(Debug)]
pub struct Allocator {
    max_allocation: usize,
    max_total_allocation: usize,
    max_allocation_panics: bool,
    allocation_backtraces: bool,
    /// The page size
    page_size: usize,
    /// The shadow offsets
    shadow_offset: usize,
    /// The shadow bit
    shadow_bit: usize,
    /// The reserved (pre-allocated) shadow mapping
    pre_allocated_shadow_mappings: Vec<ReservedMut>,
    /// Whether we've pre_allocated a shadow mapping:
    using_pre_allocated_shadow_mapping: bool,
    /// All tracked allocations
    allocations: HashMap<usize, AllocationMetadata>,
    /// All mappings
    mappings: HashMap<usize, MmapMut>,
    /// The shadow memory pages
    shadow_pages: RangeSet<usize>,
    /// A list of allocations
    allocation_queue: BTreeMap<usize, Vec<AllocationMetadata>>,
    /// The size of the largest allocation
    largest_allocation: usize,
    /// The total size of all allocations combined
    total_allocation_size: usize,
    /// The base address of the shadow memory
    base_mapping_addr: usize,
    /// The current mapping address
    current_mapping_addr: usize,
}

macro_rules! map_to_shadow {
    ($self:expr, $address:expr) => {
        $self.shadow_offset + (($address >> 3) & ((1 << ($self.shadow_bit + 1)) - 1))
    };
}

/// Metadata for an allocation
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AllocationMetadata {
    /// The address of the allocation
    pub address: usize,
    /// The size of the allocation
    pub size: usize,
    /// The actual allocated size, including metadata
    pub actual_size: usize,
    /// A backtrace to the allocation location
    pub allocation_site_backtrace: Option<Backtrace>,
    /// A backtrace to the location where this memory has been released
    pub release_site_backtrace: Option<Backtrace>,
    /// If the allocation has been freed
    pub freed: bool,
    /// If the allocation was done with a size of 0
    pub is_malloc_zero: bool,
}

impl Allocator {
    /// Creates a new [`Allocator`] (not supported on this platform!)
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_vendor = "apple",
        all(
            any(target_arch = "aarch64", target_arch = "x86_64"),
            target_os = "android"
        )
    )))]
    #[must_use]
    pub fn new(_: FuzzerOptions) -> Self {
        todo!("Shadow region not yet supported for this platform!");
    }

    /// Creates a new [`Allocator`]
    #[cfg(any(
        windows,
        target_os = "linux",
        target_vendor = "apple",
        all(
            any(target_arch = "aarch64", target_arch = "x86_64"),
            target_os = "android"
        )
    ))]
    #[must_use]
    pub fn new(options: &FuzzerOptions) -> Self {
        Self {
            max_allocation: options.max_allocation,
            max_allocation_panics: options.max_allocation_panics,
            max_total_allocation: options.max_total_allocation,
            allocation_backtraces: options.allocation_backtraces,
            ..Self::default()
        }
    }

    /// Retreive the shadow bit used by this allocator.
    #[must_use]
    pub fn shadow_bit(&self) -> u32 {
        self.shadow_bit as u32
    }

    #[inline]
    #[must_use]
    fn round_up_to_page(&self, size: usize) -> usize {
        ((size + self.page_size) / self.page_size) * self.page_size
    }

    #[inline]
    #[must_use]
    fn round_down_to_page(&self, value: usize) -> usize {
        (value / self.page_size) * self.page_size
    }

    fn find_smallest_fit(&mut self, size: usize) -> Option<AllocationMetadata> {
        for (current_size, list) in &mut self.allocation_queue {
            if *current_size >= size {
                if let Some(metadata) = list.pop() {
                    return Some(metadata);
                }
            }
        }
        None
    }

    /// Allocate a new allocation of the given size.
    #[must_use]
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn alloc(&mut self, size: usize, _alignment: usize) -> *mut c_void {
        let mut is_malloc_zero = false;
        let size = if size == 0 {
            // log::warn!("zero-sized allocation!");
            is_malloc_zero = true;
            16
        } else {
            size
        };
        if size > self.max_allocation {
            #[allow(clippy::manual_assert)]
            if self.max_allocation_panics {
                panic!("ASAN: Allocation is too large: 0x{size:x}");
            }

            return std::ptr::null_mut();
        }
        let rounded_up_size = self.round_up_to_page(size) + 2 * self.page_size;

        if self.total_allocation_size + rounded_up_size > self.max_total_allocation {
            return std::ptr::null_mut();
        }
        self.total_allocation_size += rounded_up_size;

        let metadata = if let Some(mut metadata) = self.find_smallest_fit(rounded_up_size) {
            //log::trace!("reusing allocation at {:x}, (actual mapping starts at {:x}) size {:x}", metadata.address, metadata.address - self.page_size, size);
            metadata.is_malloc_zero = is_malloc_zero;
            metadata.size = size;
            if self.allocation_backtraces {
                metadata.allocation_site_backtrace = Some(Backtrace::new_unresolved());
            }
            metadata
        } else {
            // log::trace!("{:x}, {:x}", self.current_mapping_addr, rounded_up_size);
            let mapping = match MmapOptions::new(rounded_up_size)
                .unwrap()
                .with_address(self.current_mapping_addr)
                .map_mut()
            {
                Ok(mapping) => mapping,
                Err(err) => {
                    log::error!("An error occurred while mapping memory: {err:?}");
                    return std::ptr::null_mut();
                }
            };
            self.current_mapping_addr += ((rounded_up_size
                + MmapOptions::allocation_granularity())
                / MmapOptions::allocation_granularity())
                * MmapOptions::allocation_granularity();

            self.map_shadow_for_region(
                mapping.as_ptr() as usize,
                mapping.as_ptr().add(rounded_up_size) as usize,
                false,
            );
            let address = mapping.as_ptr() as usize;
            self.mappings.insert(address, mapping);

            let mut metadata = AllocationMetadata {
                address,
                size,
                actual_size: rounded_up_size,
                ..AllocationMetadata::default()
            };
            if self.allocation_backtraces {
                metadata.allocation_site_backtrace = Some(Backtrace::new_unresolved());
            }

            metadata
        };

        self.largest_allocation = std::cmp::max(self.largest_allocation, metadata.actual_size);
        // unpoison the shadow memory for the allocation itself
        Self::unpoison(
            map_to_shadow!(self, metadata.address + self.page_size),
            size,
        );
        let address = (metadata.address + self.page_size) as *mut c_void;

        self.allocations.insert(address as usize, metadata);
        // log::trace!("serving address: {:?}, size: {:x}", address, size);
        address
    }

    /// Releases the allocation at the given address.
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn release(&mut self, ptr: *mut c_void) {
        //log::trace!("freeing address: {:?}", ptr);
        let Some(metadata) = self.allocations.get_mut(&(ptr as usize)) else {
            if !ptr.is_null() {
                AsanErrors::get_mut()
                    .report_error(AsanError::UnallocatedFree((ptr as usize, Backtrace::new())));
            }
            return;
        };

        if metadata.freed {
            AsanErrors::get_mut().report_error(AsanError::DoubleFree((
                ptr as usize,
                metadata.clone(),
                Backtrace::new(),
            )));
        }
        let shadow_mapping_start = map_to_shadow!(self, ptr as usize);

        metadata.freed = true;
        if self.allocation_backtraces {
            metadata.release_site_backtrace = Some(Backtrace::new_unresolved());
        }

        // poison the shadow memory for the allocation
        Self::poison(shadow_mapping_start, metadata.size);
    }

    /// Finds the metadata for the allocation at the given address.
    pub fn find_metadata(
        &mut self,
        ptr: usize,
        hint_base: usize,
    ) -> Option<&mut AllocationMetadata> {
        let mut metadatas: Vec<&mut AllocationMetadata> = self.allocations.values_mut().collect();
        metadatas.sort_by(|a, b| a.address.cmp(&b.address));
        let mut offset_to_closest = i64::max_value();
        let mut closest = None;
        let ptr: i64 = ptr.try_into().unwrap();
        for metadata in metadatas {
            let address: i64 = metadata.address.try_into().unwrap();
            let new_offset = if hint_base == metadata.address {
                (ptr - address).abs()
            } else {
                std::cmp::min(offset_to_closest, (ptr - address).abs())
            };
            if new_offset < offset_to_closest {
                offset_to_closest = new_offset;
                closest = Some(metadata);
            }
        }
        closest
    }

    /// Resets the allocator contents
    pub fn reset(&mut self) {
        let mut tmp_allocations = Vec::new();
        for (address, mut allocation) in self.allocations.drain() {
            if !allocation.freed {
                tmp_allocations.push(allocation);
                continue;
            }
            // First poison the memory.
            Self::poison(map_to_shadow!(self, address), allocation.size);

            // Reset the allocaiton metadata object
            allocation.size = 0;
            allocation.freed = false;
            allocation.allocation_site_backtrace = None;
            allocation.release_site_backtrace = None;

            // Move the allocation from the allocations to the to-be-allocated queues
            self.allocation_queue
                .entry(allocation.actual_size)
                .or_default()
                .push(allocation);
        }

        for allocation in tmp_allocations {
            self.allocations
                .insert(allocation.address + self.page_size, allocation);
        }

        self.total_allocation_size = 0;
    }

    /// Gets the usable size of the allocation, by allocated pointer
    pub fn get_usable_size(&self, ptr: *mut c_void) -> usize {
        match self.allocations.get(&(ptr as usize)) {
            Some(metadata) => metadata.size,
            None => {
                panic!(
                    "Attempted to get_usable_size on a pointer ({ptr:?}) which was not allocated!"
                );
            }
        }
    }

    fn unpoison(start: usize, size: usize) {
        // log::trace!("unpoisoning {:x} for {:x}", start, size / 8);
        unsafe {
            std::slice::from_raw_parts_mut(start as *mut u8, size / 8).fill(0xff);

            let remainder = size % 8;
            if remainder > 0 {
                let mut current_value = ((start + size / 8) as *const u8).read();
                current_value = current_value | (0xff << (8 - remainder));
                ((start + size / 8) as *mut u8).write(current_value);
            }
        }
    }

    /// Poisonn an area in memory
    pub fn poison(start: usize, size: usize) {
        // log::trace!("poisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            std::slice::from_raw_parts_mut(start as *mut u8, size / 8).fill(0x0);

            let remainder = size % 8;
            if remainder > 0 {
                let mask = !(0xff << (8 - remainder));
                let mut current_value = ((start + size / 8) as *const u8).read();

                current_value = current_value & mask;
                ((start + size / 8) as *mut u8).write(current_value);
            }
        }
    }

    /// Map shadow memory for a region, and optionally unpoison it
    pub fn map_shadow_for_region(
        &mut self,
        start: usize,
        end: usize,
        unpoison: bool,
    ) -> (usize, usize) {
        let shadow_mapping_start = map_to_shadow!(self, start);

        let shadow_start = self.round_down_to_page(shadow_mapping_start);
        let shadow_end = self.round_up_to_page((end - start) / 8 + self.page_size + shadow_start);
        if self.using_pre_allocated_shadow_mapping {
            log::trace!(
                "map_shadow_for_region start: {:x}, end {:x}, size {:x}, shadow {:x}-{:x}",
                start,
                end,
                end - start,
                shadow_start,
                shadow_end
            );
            let mut newly_committed_regions = Vec::new();
            for gap in self.shadow_pages.gaps(&(shadow_start..shadow_end)) {
                let mut new_reserved_region = None;
                for reserved in &mut self.pre_allocated_shadow_mappings {
                    if gap.start >= reserved.start() && gap.end <= reserved.end() {
                        let mut to_be_commited =
                            reserved.split_off(gap.start - reserved.start()).unwrap();

                        if to_be_commited.end() > gap.end {
                            let upper = to_be_commited
                                .split_off(gap.end - to_be_commited.start())
                                .unwrap();
                            new_reserved_region = Some(upper);
                        }
                        let commited: MmapMut = to_be_commited
                            .try_into()
                            .expect("Failed to commit reserved shadow memory");
                        newly_committed_regions.push(commited);
                        break;
                    }
                }

                if let Some(new_reserved_region) = new_reserved_region {
                    self.pre_allocated_shadow_mappings.push(new_reserved_region);
                }
            }
            for newly_committed_region in newly_committed_regions {
                self.shadow_pages
                    .insert(newly_committed_region.start()..newly_committed_region.end());
                self.mappings
                    .insert(newly_committed_region.start(), newly_committed_region);
            }
        }

        if unpoison {
            Self::unpoison(shadow_mapping_start, end - start);
        }

        (shadow_mapping_start, (end - start) / 8 + 1)
    }

    /// Checks whether the given address up till size is valid unpoisoned shadow memory.
    /// TODO: check edge cases
    #[inline]
    #[must_use]
    pub fn check_shadow(&mut self, address: *const c_void, size: usize) -> bool {
        if size == 0 || !self.is_managed(address as *mut c_void) {
            return true;
        }
        let address = address as usize;
        let shadow_size = size / 8;

        let shadow_addr = map_to_shadow!(self, address);

        // self.map_shadow_for_region(address, address + size, false);

        log::info!(
            "check_shadow: {:x}, {:x}, {:x}, {:x}",
            address,
            shadow_size,
            shadow_addr,
            size
        );

        let offset = address & 7;
        // if we are not aligned to 8 bytes, we need to check the high bits of the shadow
        if offset != 0 {
            let val = (unsafe { (shadow_addr as *const u16).read() }) >> offset;
            let mask = (1 << (size % 9)) - 1;
            if val & mask != mask {
                return false;
            }
        }

        if size >= 8 {
            let buf =
                unsafe { std::slice::from_raw_parts_mut(shadow_addr as *mut u8, shadow_size) };
            let (prefix, aligned, suffix) = unsafe { buf.align_to::<u128>() };
            if prefix.iter().all(|&x| x == 0xff)
                && suffix.iter().all(|&x| x == 0xff)
                && aligned
                    .iter()
                    .all(|&x| x == 0xffffffffffffffffffffffffffffffffu128)
            {
                if size % 8 != 0 {
                    let val = unsafe { ((shadow_addr + shadow_size) as *mut u8).read() };
                    let mask = (1 << (size % 8)) - 1;
                    if val & mask != mask {
                        return false;
                    }
                }
                return true;
            }
        }
        if size % 8 != 0 {
            let val = unsafe { ((shadow_addr + shadow_size) as *mut u8).read() };
            let mask = (1 << (size % 8)) - 1;
            if val & mask != mask {
                return false;
            }
        }
        return true;
    }
    /// Maps the address to a shadow address
    #[inline]
    #[must_use]
    pub fn map_to_shadow(&self, start: usize) -> usize {
        map_to_shadow!(self, start)
    }

    /// Checks if the currennt address is one of ours
    #[inline]
    pub fn is_managed(&self, ptr: *mut c_void) -> bool {
        //self.allocations.contains_key(&(ptr as usize))
        self.shadow_offset <= ptr as usize && (ptr as usize) < self.current_mapping_addr
    }

    /// Checks if any of the allocations has not been freed
    pub fn check_for_leaks(&self) {
        for metadata in self.allocations.values() {
            if !metadata.freed {
                AsanErrors::get_mut()
                    .report_error(AsanError::Leak((metadata.address, metadata.clone())));
            }
        }
    }

    /// Unpoison all the memory that is currently mapped with read/write permissions.
    pub fn unpoison_all_existing_memory(&mut self) {
        log::trace!(
            "Shadow Mapping: {:#x}-{:#x}",
            self.shadow_offset,
            self.current_mapping_addr
        );
        RangeDetails::enumerate_with_prot(
            PageProtection::Read,
            &mut |range: &RangeDetails| -> bool {
                let start = range.memory_range().base_address().0 as usize;
                let end = start + range.memory_range().size();
                log::trace!(
                    "Mapping: {:#x}-{:#x}, is_managed: {}",
                    start,
                    end,
                    self.is_managed(start as *mut c_void)
                );

                if !self.is_managed(start as *mut c_void) {
                    log::trace!("Unpoisoning: {:#x}-{:#x}", start, end);
                    self.map_shadow_for_region(start, end, true);
                }

                return true;
            },
        );
    }

    /// Initialize the allocator, making sure a valid shadow bit is selected.
    pub fn init(&mut self) {
        // probe to find a usable shadow bit:
        if self.shadow_bit != 0 {
            return;
        }

        let mut shadow_bit = 0;

        let mut occupied_ranges: Vec<(usize, usize)> = vec![];
        // max(userspace address) this is usually 0x8_0000_0000_0000 - 1 on x64 linux.
        let mut userspace_max: usize = 0;

        // Enumerate memory ranges that are already occupied.

        RangeDetails::enumerate_with_prot(
            PageProtection::NoAccess,
            &mut |range: &RangeDetails| -> bool {
                let start = range.memory_range().base_address().0 as usize;
                let end = start + range.memory_range().size();
                log::trace!("Start: {:#x}, end: {:#x}", start, end);
                occupied_ranges.push((start, end));
                let base: usize = 2;
                // On x64, if end > 2**48, then that's in vsyscall or something.
                #[cfg(all(unix, target_arch = "x86_64"))]
                if end <= base.pow(48) && end > userspace_max {
                    userspace_max = end;
                }

                #[cfg(all(not(unix), target_arch = "x86_64"))]
                if (end >> 3) <= base.pow(44) && (end >> 3) > userspace_max {
                    userspace_max = end >> 3;
                }

                // On aarch64, if end > 2**52, then range is not in userspace
                #[cfg(target_arch = "aarch64")]
                if end <= base.pow(52) && end > userspace_max {
                    userspace_max = end;
                }

                return true;
            },
        );

        let mut maxbit = 0;
        for power in 1..64 {
            let base: usize = 2;
            if base.pow(power) > userspace_max {
                maxbit = power;
                break;
            }
        }

        {
            for try_shadow_bit in &[maxbit, maxbit - 4, maxbit - 3, maxbit - 2] {
                let addr: usize = 1 << try_shadow_bit;
                let shadow_start = addr;
                let shadow_end = addr + addr + addr;
                let mut good_candidate = true;
                // check if the proposed shadow bit overlaps with occupied ranges.
                for (start, end) in &occupied_ranges {
                    // log::trace!("{:x} {:x}, {:x} {:x} -> {:x} - {:x}", shadow_start, shadow_end, start, end,
                    //     shadow_start + ((start >> 3) & ((1 << (try_shadow_bit + 1)) - 1)),
                    //     shadow_start + ((end >> 3) & ((1 << (try_shadow_bit + 1)) - 1))
                    // );
                    if (shadow_start <= *end) && (*start <= shadow_end) {
                        // log::trace!("{:x} {:x}, {:x} {:x}", shadow_start, shadow_end, start, end);
                        log::warn!("shadow_bit {try_shadow_bit:x} is not suitable");
                        good_candidate = false;
                        break;
                    }
                    //check that the entire range's shadow is within the candidate shadow memory space
                    if (shadow_start + ((start >> 3) & ((1 << (try_shadow_bit + 1)) - 1))
                        > shadow_end)
                        || (shadow_start + (((end >> 3) & ((1 << (try_shadow_bit + 1)) - 1)) + 1)
                            > shadow_end)
                    {
                        log::warn!(
                            "shadow_bit {try_shadow_bit:x} is not suitable (shadow out of range)"
                        );
                        good_candidate = false;
                        break;
                    }
                }

                if good_candidate {
                    // We reserve the shadow memory space of size addr*2, but don't commit it.
                    if let Ok(mapping) = MmapOptions::new(1 << (*try_shadow_bit + 1))
                        .unwrap()
                        .with_flags(MmapFlags::NO_RESERVE)
                        .with_address(addr)
                        .reserve_mut()
                    {
                        shadow_bit = (*try_shadow_bit).try_into().unwrap();

                        log::warn!("shadow_bit {shadow_bit:x} is suitable");
                        self.pre_allocated_shadow_mappings.push(mapping);
                        self.using_pre_allocated_shadow_mapping = true;
                        break;
                    }
                    log::warn!("shadow_bit {try_shadow_bit:x} is not suitable - failed to allocate shadow memory");
                }
            }
        }

        // assert!(shadow_bit != 0);
        // attempt to pre-map the entire shadow-memory space

        let addr: usize = 1 << shadow_bit;

        self.shadow_offset = 1 << shadow_bit;
        self.shadow_bit = shadow_bit;
        self.base_mapping_addr = addr + addr + addr;
        self.current_mapping_addr = addr + addr + addr;
    }
}

impl Default for Allocator {
    /// Creates a new [`Allocator`] (not supported on this platform!)
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_vendor = "apple",
        all(
            any(target_arch = "aarch64", target_arch = "x86_64"),
            target_os = "android"
        )
    )))]
    fn default() -> Self {
        todo!("Shadow region not yet supported for this platform!");
    }

    fn default() -> Self {
        let page_size = MmapOptions::page_size();

        Self {
            max_allocation: 1 << 30,
            max_allocation_panics: false,
            max_total_allocation: 1 << 32,
            allocation_backtraces: false,
            page_size,
            pre_allocated_shadow_mappings: Vec::new(),
            using_pre_allocated_shadow_mapping: false,
            mappings: HashMap::new(),
            shadow_offset: 0,
            shadow_bit: 0,
            allocations: HashMap::new(),
            shadow_pages: RangeSet::new(),
            allocation_queue: BTreeMap::new(),
            largest_allocation: 0,
            total_allocation_size: 0,
            base_mapping_addr: 0,
            current_mapping_addr: 0,
        }
    }
}

#[test]
fn check_shadow() {
    let mut allocator = Allocator::default();
    allocator.init();

    let allocation = unsafe { allocator.alloc(8, 8) };
    assert!(!allocation.is_null());
    assert!(allocator.check_shadow(allocation, 1) == true);
    assert!(allocator.check_shadow(allocation, 2) == true);
    assert!(allocator.check_shadow(allocation, 3) == true);
    assert!(allocator.check_shadow(allocation, 4) == true);
    assert!(allocator.check_shadow(allocation, 5) == true);
    assert!(allocator.check_shadow(allocation, 6) == true);
    assert!(allocator.check_shadow(allocation, 7) == true);
    assert!(allocator.check_shadow(allocation, 8) == true);
    assert!(allocator.check_shadow(allocation, 9) == false);
    assert!(allocator.check_shadow(allocation, 10) == false);
    assert!(allocator.check_shadow(unsafe { allocation.offset(1) }, 7) == true);
    assert!(allocator.check_shadow(unsafe { allocation.offset(2) }, 6) == true);
    assert!(allocator.check_shadow(unsafe { allocation.offset(3) }, 5) == true);
    assert!(allocator.check_shadow(unsafe { allocation.offset(4) }, 4) == true);
    assert!(allocator.check_shadow(unsafe { allocation.offset(5) }, 3) == true);
    assert!(allocator.check_shadow(unsafe { allocation.offset(6) }, 2) == true);
    assert!(allocator.check_shadow(unsafe { allocation.offset(7) }, 1) == true);
    assert!(allocator.check_shadow(unsafe { allocation.offset(8) }, 0) == true);
    assert!(allocator.check_shadow(unsafe { allocation.offset(9) }, 1) == false);
    assert!(allocator.check_shadow(unsafe { allocation.offset(9) }, 8) == false);
    assert!(allocator.check_shadow(unsafe { allocation.offset(1) }, 9) == false);
    assert!(allocator.check_shadow(unsafe { allocation.offset(1) }, 8) == false);
    assert!(allocator.check_shadow(unsafe { allocation.offset(2) }, 8) == false);
    assert!(allocator.check_shadow(unsafe { allocation.offset(3) }, 8) == false);
}
