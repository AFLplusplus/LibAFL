#[cfg(any(
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
    target_os = "linux",
    target_vendor = "apple",
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_os = "android"
    )
))]
use mmap_rs::{MemoryAreas, MmapFlags, MmapMut, MmapOptions, ReservedMut};
use nix::libc::memset;
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
    pre_allocated_shadow_mappings: HashMap<(usize, usize), ReservedMut>,
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
        // log::trace!("unpoisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            // log::trace!("memset: {:?}", start as *mut c_void);
            memset(start as *mut c_void, 0xff, size / 8);

            let remainder = size % 8;
            if remainder > 0 {
                // log::trace!("remainder: {:x}, offset: {:x}", remainder, start + size / 8);
                memset(
                    (start + size / 8) as *mut c_void,
                    (0xff << (8 - remainder)) & 0xff,
                    1,
                );
            }
        }
    }

    /// Poisonn an area in memory
    pub fn poison(start: usize, size: usize) {
        // log::trace!("poisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            // log::trace!("memset: {:?}", start as *mut c_void);
            memset(start as *mut c_void, 0x00, size / 8);

            let remainder = size % 8;
            if remainder > 0 {
                // log::trace!("remainder: {:x}, offset: {:x}", remainder, start + size / 8);
                memset((start + size / 8) as *mut c_void, 0x00, 1);
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
        // I'm not sure this works as planned. The same address appearing as start and end is mapped to
        // different addresses.
        let shadow_end = self.round_up_to_page((end - start) / 8) + self.page_size + shadow_start;
        log::trace!(
            "map_shadow_for_region start: {:x}, end {:x}, size {:x}, shadow {:x}-{:x}",
            start,
            end,
            end - start,
            shadow_start,
            shadow_end
        );
        if self.pre_allocated_shadow_mappings.is_empty() {
            for range in self.shadow_pages.gaps(&(shadow_start..shadow_end)) {
                /*
                log::trace!(
                    "range: {:x}-{:x}, pagesize: {}",
                    range.start, range.end, self.page_size
                );
                */
                let mapping = MmapOptions::new(range.end - range.start - 1)
                    .unwrap()
                    .with_address(range.start)
                    .map_mut()
                    .expect("An error occurred while mapping shadow memory");

                self.mappings.insert(range.start, mapping);
            }

            log::trace!("adding shadow pages {:x} - {:x}", shadow_start, shadow_end);
            self.shadow_pages.insert(shadow_start..shadow_end);
        } else {
            let mut new_shadow_mappings = Vec::new();
            for gap in self.shadow_pages.gaps(&(shadow_start..shadow_end)) {
                for ((pa_start, pa_end), shadow_mapping) in &mut self.pre_allocated_shadow_mappings
                {
                    if *pa_start <= gap.start && gap.start < *pa_start + shadow_mapping.len() {
                        log::trace!("pa_start: {:x}, pa_end {:x}, gap.start {:x}, shadow_mapping.ptr {:x}, shadow_mapping.len {:x}",
                         *pa_start, *pa_end, gap.start, shadow_mapping.as_ptr() as usize, shadow_mapping.len());

                        // Split the preallocated mapping into two parts, keeping the
                        // part before the gap and returning the part starting with the gap as a new mapping
                        let mut start_mapping =
                            shadow_mapping.split_off(gap.start - *pa_start).unwrap();

                        // Split the new mapping into two parts,
                        // keeping the part holding the gap and returning the part starting after the gap as a new mapping
                        let end_mapping = start_mapping.split_off(gap.end - gap.start).unwrap();

                        //Push the new after-the-gap mapping to the list of mappings to be added
                        new_shadow_mappings.push(((gap.end, *pa_end), end_mapping));

                        // Insert the new gap mapping into the list of mappings
                        self.mappings
                            .insert(gap.start, start_mapping.try_into().unwrap());

                        break;
                    }
                }
            }
            for new_shadow_mapping in new_shadow_mappings {
                log::trace!(
                    "adding pre_allocated_shadow_mappings and shadow pages {:x} - {:x}",
                    new_shadow_mapping.0 .0,
                    new_shadow_mapping.0 .1
                );
                self.pre_allocated_shadow_mappings
                    .insert(new_shadow_mapping.0, new_shadow_mapping.1);

                self.shadow_pages
                    .insert(new_shadow_mapping.0 .0..new_shadow_mapping.0 .1);
            }
        }

        // log::trace!("shadow_mapping_start: {:x}, shadow_size: {:x}", shadow_mapping_start, (end - start) / 8);
        if unpoison {
            Self::unpoison(shadow_mapping_start, end - start);
        }

        (shadow_mapping_start, (end - start) / 8)
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
        self.base_mapping_addr <= ptr as usize && (ptr as usize) < self.current_mapping_addr
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
        RangeDetails::enumerate_with_prot(PageProtection::NoAccess, &mut |range: &RangeDetails| {
            if range.protection() as u32 & PageProtection::ReadWrite as u32 != 0 {
                let start = range.memory_range().base_address().0 as usize;
                let end = start + range.memory_range().size();
                if !self.pre_allocated_shadow_mappings.is_empty() && start == 1 << self.shadow_bit {
                    return true;
                }
                self.map_shadow_for_region(start, end, true);
            }
            true
        });
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
        for area in MemoryAreas::open(None).unwrap() {
            let start = area.as_ref().unwrap().start();
            let end = area.unwrap().end();
            occupied_ranges.push((start, end));
            // log::trace!("Occupied {:x} {:x}", start, end);
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
        }

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
                        log::trace!("{:x} {:x}, {:x} {:x}", shadow_start, shadow_end, start, end);
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
                        log::trace!(
                            "adding pre_allocated_shadow_mappings {:x} - {:x} with size {:}",
                            addr,
                            (addr + (1 << (shadow_bit + 1))),
                            mapping.len()
                        );

                        self.pre_allocated_shadow_mappings
                            .insert((addr, (addr + (1 << (shadow_bit + 1)))), mapping);
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
            pre_allocated_shadow_mappings: HashMap::new(),
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
