#[cfg(any(
    windows,
    target_os = "linux",
    target_vendor = "apple",
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_os = "android"
    )
))]
use alloc::collections::BTreeMap;
#[cfg(any(
    windows,
    target_os = "linux",
    target_vendor = "apple",
    all(
        any(target_arch = "aarch64", target_arch = "x86_64"),
        target_os = "android"
    )
))]
use core::ffi::c_void;

use backtrace::Backtrace;
use frida_gum::{PageProtection, RangeDetails};
use libafl_bolts::cli::FuzzerOptions;
#[cfg(target_vendor = "apple")]
use mach_sys::{
    kern_return::KERN_SUCCESS,
    message::mach_msg_type_number_t,
    traps::mach_task_self,
    vm::mach_vm_region_recurse,
    vm_prot::VM_PROT_READ,
    vm_region::{vm_region_recurse_info_t, vm_region_submap_info_64},
    vm_types::{mach_vm_address_t, mach_vm_size_t, natural_t},
};
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

#[cfg(target_vendor = "apple")]
const VM_REGION_SUBMAP_INFO_COUNT_64: mach_msg_type_number_t = 19;

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
    /// Whether we've pre allocated a shadow mapping:
    using_pre_allocated_shadow_mapping: bool,
    /// All tracked allocations
    allocations: BTreeMap<usize, AllocationMetadata>,
    /// All mappings
    mappings: BTreeMap<usize, MmapMut>,
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
    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn alloc(&mut self, size: usize, _alignment: usize) -> *mut c_void {
        let mut is_malloc_zero = false;
        let size = if size == 0 {
            is_malloc_zero = true;
            16
        } else {
            size
        };
        if size > self.max_allocation {
            #[expect(clippy::manual_assert)]
            if self.max_allocation_panics {
                panic!("ASAN: Allocation is too large: 0x{size:x}");
            }

            return core::ptr::null_mut();
        }
        let rounded_up_size = self.round_up_to_page(size) + 2 * self.page_size;

        if self.total_allocation_size + rounded_up_size > self.max_total_allocation {
            return core::ptr::null_mut();
        }
        self.total_allocation_size += rounded_up_size;

        let metadata = if let Some(mut metadata) = self.find_smallest_fit(rounded_up_size) {
            metadata.is_malloc_zero = is_malloc_zero;
            metadata.size = size;
            if self.allocation_backtraces {
                metadata.allocation_site_backtrace = Some(Backtrace::new_unresolved());
            }
            metadata
        } else {
            // log::info!(
            //     "Mapping {:x}, size {rounded_up_size:x}",
            //     self.current_mapping_addr
            // );
            let mapping = match MmapOptions::new(rounded_up_size)
                .unwrap()
                .with_address(self.current_mapping_addr)
                .map_mut()
            {
                Ok(mapping) => mapping,
                Err(err) => {
                    log::error!("An error occurred while mapping memory: {err:?}");
                    return core::ptr::null_mut();
                }
            };
            self.current_mapping_addr += ((rounded_up_size
                + MmapOptions::allocation_granularity())
                / MmapOptions::allocation_granularity())
                * MmapOptions::allocation_granularity();

            self.map_shadow_for_region(
                mapping.as_ptr() as usize,
                unsafe { mapping.as_ptr().add(rounded_up_size) as usize },
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

        self.largest_allocation = core::cmp::max(self.largest_allocation, metadata.actual_size);
        // unpoison the shadow memory for the allocation itself
        unsafe {
            Self::unpoison(
                map_to_shadow!(self, metadata.address + self.page_size),
                size,
            );
        }
        let address = (metadata.address + self.page_size) as *mut c_void;

        self.allocations.insert(address as usize, metadata);
        // log::info!("serving address: {address:?}, size: {size:x}");
        address
    }

    /// Releases the allocation at the given address.
    #[expect(clippy::missing_safety_doc)]
    pub unsafe fn release(&mut self, ptr: *mut c_void) {
        // log::info!("releasing {:?}", ptr);
        let Some(metadata) = self.allocations.get_mut(&(ptr as usize)) else {
            if !ptr.is_null()
                && AsanErrors::get_mut_blocking()
                    .report_error(AsanError::UnallocatedFree((ptr as usize, Backtrace::new())))
            {
                panic!("ASAN: Crashing target!");
            }
            return;
        };

        if metadata.freed
            && AsanErrors::get_mut_blocking().report_error(AsanError::DoubleFree((
                ptr as usize,
                metadata.clone(),
                Backtrace::new(),
            )))
        {
            panic!("ASAN: Crashing target!");
        }
        let shadow_mapping_start = map_to_shadow!(self, ptr as usize);

        metadata.freed = true;
        if self.allocation_backtraces {
            metadata.release_site_backtrace = Some(Backtrace::new_unresolved());
        }

        // poison the shadow memory for the allocation
        unsafe {
            Self::poison(shadow_mapping_start, metadata.size);
        }
    }

    /// Finds the metadata for the allocation at the given address.
    pub fn find_metadata(
        &mut self,
        ptr: usize,
        hint_base: usize,
    ) -> Option<&mut AllocationMetadata> {
        let mut metadatas: Vec<&mut AllocationMetadata> = self.allocations.values_mut().collect();
        metadatas.sort_by(|a, b| a.address.cmp(&b.address));
        let mut offset_to_closest = i64::MAX;
        let mut closest = None;
        let ptr: i64 = ptr.try_into().unwrap();
        for metadata in metadatas {
            let address: i64 = metadata.address.try_into().unwrap();
            let new_offset = if hint_base == metadata.address {
                (ptr - address).abs()
            } else {
                core::cmp::min(offset_to_closest, (ptr - address).abs())
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
        while let Some((address, mut allocation)) = self.allocations.pop_first() {
            if !allocation.freed {
                tmp_allocations.push(allocation);
                continue;
            }
            // First poison the memory.
            unsafe {
                Self::poison(map_to_shadow!(self, address), allocation.size);
            }

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

    /// Unpoison an area in memory
    ///
    /// # Safety
    /// start needs to be a valid address, We need to be able to fill `size / 8` bytes.
    unsafe fn unpoison(start: usize, size: usize) {
        unsafe {
            core::slice::from_raw_parts_mut(start as *mut u8, size / 8).fill(0xff);

            let remainder = size % 8;
            if remainder > 0 {
                let mut current_value = ((start + size / 8) as *const u8).read();
                current_value |= 0xff << (8 - remainder);
                ((start + size / 8) as *mut u8).write(current_value);
            }
        }
    }

    /// Poison an area in memory
    ///
    /// # Safety
    /// start needs to be a valid address, We need to be able to fill `size / 8` bytes.
    pub unsafe fn poison(start: usize, size: usize) {
        unsafe {
            core::slice::from_raw_parts_mut(start as *mut u8, size / 8).fill(0x0);

            let remainder = size % 8;
            if remainder > 0 {
                let mask = !(0xff << (8 - remainder));
                let mut current_value = ((start + size / 8) as *const u8).read();

                current_value &= mask;
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
        // log::trace!("map_shadow_for_region: {:x}, {:x}", start, end);
        let shadow_start = self.round_down_to_page(shadow_mapping_start);
        let shadow_end = self.round_up_to_page((end - start) / 8 + self.page_size + shadow_start);
        // log::trace!(
        //     "map_shadow_for_region: shadow_start {:x}, shadow_end {:x}",
        //     shadow_start,
        //     shadow_end
        // );
        if self.using_pre_allocated_shadow_mapping {
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
                // log::trace!(
                //     "committed shadow pages: start {:x}, end {:x}",
                //     newly_committed_region.start(),
                //     newly_committed_region.end()
                // );
                self.shadow_pages
                    .insert(newly_committed_region.start()..newly_committed_region.end());
                self.mappings
                    .insert(newly_committed_region.start(), newly_committed_region);
            }
        }

        if unpoison {
            unsafe {
                Self::unpoison(shadow_mapping_start, end - start);
            }
        }

        (shadow_mapping_start, (end - start) / 8 + 1)
    }

    #[inline]
    #[must_use]
    fn check_shadow_aligned(&mut self, address: *const c_void, size: usize) -> bool {
        assert_eq!(
            (address as usize) & 7,
            0,
            "check_shadow_aligned used when address is not aligned. Use check_shadow"
        );
        assert_eq!(
            size & 7,
            0,
            "check_shadow_aligned used when size is not aligned. Use check_shadow"
        );

        if size == 0 {
            return true;
        }

        let shadow_addr = map_to_shadow!(self, (address as usize));
        let shadow_size = size >> 3;
        let buf = unsafe { core::slice::from_raw_parts_mut(shadow_addr as *mut u8, shadow_size) };
        let (prefix, aligned, suffix) = unsafe { buf.align_to::<u128>() };
        if !prefix.iter().all(|&x| x == 0xff)
            || !suffix.iter().all(|&x| x == 0xff)
            || !aligned
                .iter()
                .all(|&x| x == 0xffffffffffffffffffffffffffffffffu128)
        {
            return false;
        }

        true
    }
    /// Checks whether the given address up till size is valid unpoisoned shadow memory.
    /// TODO: check edge cases
    #[inline]
    #[must_use]
    pub fn check_shadow(&mut self, address: *const c_void, size: usize) -> bool {
        //the algorithm for check_shadow is as follows:
        //1. we first check if its managed. if is not then exit
        //2. we check if it is aligned. this should be 99% of accesses. If it is do an aligned check and leave
        //3. if it is not split the check into 3 parts: the pre-aligment bytes, the aligned portion, and the post alignment posts
        //3. The prealignment bytes are the unaligned bytes (if any) located in the qword preceding the aligned portion. Perform a specialied check to ensure that the bytes from [start, align(start, 8)) are valid. In this case align(start,8) aligns start to the next 8 byte boundary.
        //4. The aligned check is where the address and the size is 8 byte aligned. Use check_shadow_aligned to check it
        //5. The post-alignment is the same as pre-alignment except it is the qword following the aligned portion. Use a specialized check to ensure that [end & ~7, end) is valid.

        if size == 0 {
            return true;
        }

        if !self.is_managed(address.cast_mut()) {
            return true;
        }

        //fast path. most buffers are likely 8 byte aligned in size and address
        if (address as usize).trailing_zeros() >= 3 && size.trailing_zeros() >= 3 {
            return self.check_shadow_aligned(address, size);
        }

        //slow path. check everything
        let start_address = address as usize;
        let end_address = start_address + size;

        //8 byte align the start/end so we can use check_shadow_aligned for the majority of it
        //in the case of subqword accesses (i.e,, the entire access is located within 1 qword), aligned_start > aligned_end naturally
        let aligned_start = (start_address + 7) & !7;
        let aligned_end = end_address & !7;

        let start_offset = start_address & 7;
        let end_offset = end_address & 7;

        //if the start is unaligned
        if start_address != aligned_start {
            let start_shadow = map_to_shadow!(self, start_address);

            let start_mask: u8 = 0xff << (8 - start_offset);
            if unsafe { (start_shadow as *const u8).read() } & start_mask != start_mask {
                return false;
            }
        }

        //if this is not true then it must be a subqword access as the start will be larger than the end
        if aligned_start <= aligned_end {
            if !self
                .check_shadow_aligned(aligned_start as *const c_void, aligned_end - aligned_start)
            {
                return false;
            }

            if end_address != aligned_end {
                let end_shadow = map_to_shadow!(self, end_address);

                let end_mask = 0xff << (8 - end_offset); //we want to check from the beginning of the qword to the offset
                if unsafe { (end_shadow as *const u8).read() } & end_mask != end_mask {
                    return false;
                }
            }
        }
        // self.map_shadow_for_region(address, address + size, false);

        true
    }
    /// Maps the address to a shadow address
    #[inline]
    #[must_use]
    pub fn map_to_shadow(&self, start: usize) -> usize {
        map_to_shadow!(self, start)
    }

    /// Is this a valid and mapped shadow address?
    #[must_use]
    pub fn valid_shadow(&self, start: usize, size: usize) -> bool {
        let range_to_check = start..(start + size);
        let valid = self
            .shadow_pages
            .overlapping(&range_to_check)
            .any(|r| r.start <= start && r.end >= start + size);

        if !valid {
            log::error!("Not a valid shadow: {start:#x}!");
        }
        valid
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
            if !metadata.freed
                && AsanErrors::get_mut_blocking()
                    .report_error(AsanError::Leak((metadata.address, metadata.clone())))
            {
                unsafe {
                    println!(
                        "{:x?}",
                        core::slice::from_raw_parts(metadata.address as *const u8, metadata.size)
                    );
                };
                panic!("ASAN: Crashing target!");
            }
        }
    }

    /// Unpoison all the memory that is currently mapped with read permissions.
    #[cfg(target_vendor = "apple")]
    pub fn unpoison_all_existing_memory(&mut self) {
        let task = unsafe { mach_task_self() };
        let mut address: mach_vm_address_t = 0;
        let mut size: mach_vm_size_t = 0;
        let mut depth: natural_t = 0;

        loop {
            let mut kr;
            let mut info_count: mach_msg_type_number_t = VM_REGION_SUBMAP_INFO_COUNT_64;
            let mut info = vm_region_submap_info_64::default();
            loop {
                kr = unsafe {
                    mach_vm_region_recurse(
                        task,
                        &raw mut address,
                        &raw mut size,
                        &raw mut depth,
                        &raw mut info as vm_region_recurse_info_t,
                        &raw mut info_count,
                    )
                };

                if kr != KERN_SUCCESS {
                    break;
                }

                if info.is_submap != 0 {
                    depth += 1;
                    continue;
                }

                break;
            }

            if kr != KERN_SUCCESS {
                break;
            }

            let start = address as usize;
            let end = (address + size) as usize;

            if info.protection & VM_PROT_READ == VM_PROT_READ {
                //if its at least readable
                if self.shadow_offset <= start && end <= self.current_mapping_addr {
                    log::trace!("Reached the shadow/allocator region - skipping");
                } else {
                    log::trace!("Unpoisoning: {:#x}:{:#x}", address, address + size);
                    self.map_shadow_for_region(start, end, true);
                }
            }
            address += size;
            size = 0;
        }
    }

    /// Unpoisons all memory
    #[cfg(not(target_vendor = "apple"))]
    pub fn unpoison_all_existing_memory(&mut self) {
        RangeDetails::enumerate_with_prot(
            PageProtection::Read,
            &mut |range: &RangeDetails| -> bool {
                let start = range.memory_range().base_address().0 as usize;
                let end = start + range.memory_range().size();
                if self.shadow_offset <= start && end <= self.current_mapping_addr {
                    log::trace!("Reached the shadow/allocator region - skipping");
                } else {
                    // log::trace!("Unpoisoning: {:#x}-{:#x}", start, end);
                    self.map_shadow_for_region(start, end, true);
                }
                true
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
        #[cfg(unix)]
        let mut userspace_max: usize = 0;

        // Enumerate memory ranges that are already occupied.

        RangeDetails::enumerate_with_prot(
            PageProtection::Read,
            &mut |range: &RangeDetails| -> bool {
                let start = range.memory_range().base_address().0 as usize;
                let end = start + range.memory_range().size();
                log::trace!("New range: {start:#x}-{end:#x}");

                #[cfg(target_vendor = "apple")]
                if start >= 0x600000000000 {
                    //this is the MALLOC_NANO region. There is no point in spending time tracking this region as we hook malloc
                    return false;
                }

                occupied_ranges.push((start, end));
                // On x64, if end > 2**48, then that's in vsyscall or something.
                #[cfg(all(unix, target_arch = "x86_64"))]
                if end <= 2_usize.pow(48) && end > userspace_max {
                    userspace_max = end;
                }
                //
                // #[cfg(all(not(unix), target_arch = "x86_64"))]
                // if end <= 2_usize.pow(64) && end > userspace_max {
                //     userspace_max = end;
                // }

                // On aarch64, if end > 2**52, then range is not in userspace
                #[cfg(target_arch = "aarch64")]
                if end <= 2_usize.pow(52) && end > userspace_max {
                    userspace_max = end;
                }

                true
            },
        );

        #[cfg(unix)]
        let mut maxbit = 63;
        #[cfg(windows)]
        let maxbit = 63;
        #[cfg(unix)]
        for power in 44..64 {
            if 2_usize.pow(power) > userspace_max {
                maxbit = power;
                break;
            }
        }

        log::trace!("max bit: {maxbit}");

        {
            for try_shadow_bit in 44..=maxbit {
                let addr: usize = 1 << try_shadow_bit;
                let shadow_start = addr;
                let shadow_end = addr + addr + addr;
                let mut good_candidate = true;
                // check if the proposed shadow bit overlaps with occupied ranges.
                for (start, end) in &occupied_ranges {
                    if (shadow_start <= *end) && (*start <= shadow_end) {
                        log::trace!("{shadow_start:x} {shadow_end:x}, {start:x} {end:x}");
                        log::warn!("shadow_bit {try_shadow_bit:} is not suitable");
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
                            "shadow_bit {try_shadow_bit:} is not suitable (shadow out of range)"
                        );
                        good_candidate = false;
                        break;
                    }
                }

                if good_candidate {
                    // We reserve the shadow memory space of size addr*2, but don't commit it.
                    if let Ok(mapping) = MmapOptions::new(1 << (try_shadow_bit + 1))
                        .unwrap()
                        .with_flags(MmapFlags::NO_RESERVE)
                        .with_address(addr)
                        .reserve_mut()
                    {
                        shadow_bit = (try_shadow_bit).try_into().unwrap();

                        log::warn!("shadow_bit {shadow_bit:} is suitable");
                        log::trace!(
                            "shadow area from {:x} to {:x} pre-allocated",
                            addr,
                            addr + (1 << (try_shadow_bit + 1))
                        );
                        self.pre_allocated_shadow_mappings.push(mapping);
                        self.using_pre_allocated_shadow_mapping = true;
                        break;
                    }
                    log::warn!(
                        "shadow_bit {try_shadow_bit:} is not suitable - failed to allocate shadow memory"
                    );
                }
            }
        }

        log::warn!("shadow_bit: {shadow_bit}");
        assert!(shadow_bit != 0);

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
            mappings: BTreeMap::new(),
            shadow_offset: 0,
            shadow_bit: 0,
            allocations: BTreeMap::new(),
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
    use frida_gum::Gum;
    let _gum = Gum::obtain();
    let mut allocator = Allocator::default();
    allocator.init();

    let allocation = unsafe { allocator.alloc(8, 8) };
    assert!(!allocation.is_null());
    assert!(allocator.check_shadow(allocation, 1));
    assert!(allocator.check_shadow(allocation, 2));
    assert!(allocator.check_shadow(allocation, 3));
    assert!(allocator.check_shadow(allocation, 4));
    assert!(allocator.check_shadow(allocation, 5));
    assert!(allocator.check_shadow(allocation, 6));
    assert!(allocator.check_shadow(allocation, 7));
    assert!(allocator.check_shadow(allocation, 8));
    assert!(!allocator.check_shadow(allocation, 9));
    assert!(!allocator.check_shadow(allocation, 10));
    assert!(allocator.check_shadow(unsafe { allocation.offset(1) }, 7));
    assert!(allocator.check_shadow(unsafe { allocation.offset(2) }, 6));
    assert!(allocator.check_shadow(unsafe { allocation.offset(3) }, 5));
    assert!(allocator.check_shadow(unsafe { allocation.offset(4) }, 4));
    assert!(allocator.check_shadow(unsafe { allocation.offset(5) }, 3));
    assert!(allocator.check_shadow(unsafe { allocation.offset(6) }, 2));
    assert!(allocator.check_shadow(unsafe { allocation.offset(7) }, 1));
    assert!(allocator.check_shadow(unsafe { allocation.offset(8) }, 0));
    assert!(!allocator.check_shadow(unsafe { allocation.offset(9) }, 1));
    assert!(!allocator.check_shadow(unsafe { allocation.offset(9) }, 8));
    assert!(!allocator.check_shadow(unsafe { allocation.offset(1) }, 9));
    assert!(!allocator.check_shadow(unsafe { allocation.offset(1) }, 8));
    assert!(!allocator.check_shadow(unsafe { allocation.offset(2) }, 8));
    assert!(!allocator.check_shadow(unsafe { allocation.offset(3) }, 8));
    let allocation = unsafe { allocator.alloc(0xc, 0) };
    assert!(allocator.check_shadow(unsafe { allocation.offset(4) }, 8));
    //subqword access
    assert!(allocator.check_shadow(unsafe { allocation.offset(3) }, 2));
    //unaligned access
    assert!(allocator.check_shadow(unsafe { allocation.offset(3) }, 8));
    let allocation = unsafe { allocator.alloc(0x20, 0) };
    //access with unaligned parts at the beginning and end
    assert!(allocator.check_shadow(unsafe { allocation.offset(10) }, 21));
    //invalid, unaligned access
    assert!(!allocator.check_shadow(unsafe { allocation.offset(10) }, 29));
    let allocation = unsafe { allocator.alloc(4, 0) };
    assert!(!allocation.is_null());
    assert!(allocator.check_shadow(allocation, 1));
    assert!(allocator.check_shadow(allocation, 2));
    assert!(allocator.check_shadow(allocation, 3));
    assert!(allocator.check_shadow(allocation, 4));
    assert!(!allocator.check_shadow(allocation, 5));
    assert!(!allocator.check_shadow(allocation, 6));
    assert!(!allocator.check_shadow(allocation, 7));
    assert!(!allocator.check_shadow(allocation, 8));
    let allocation = unsafe { allocator.alloc(0xc, 0) };
    assert!(allocator.check_shadow(unsafe { allocation.offset(4) }, 8));
    let allocation = unsafe { allocator.alloc(0x3c, 0) };
    assert!(allocator.check_shadow(unsafe { allocation.offset(0x3a) }, 2));
}
