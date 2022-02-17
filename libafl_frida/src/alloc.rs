use frida_gum::{PageProtection, RangeDetails};
use hashbrown::HashMap;
use libafl::bolts::cli::FuzzerOptions;
use nix::{
    libc::memset,
    sys::mman::{mmap, MapFlags, ProtFlags},
};

use backtrace::Backtrace;
#[cfg(any(
    target_os = "linux",
    target_vendor = "apple",
    all(target_arch = "aarch64", target_os = "android")
))]
use libc::{sysconf, _SC_PAGESIZE};
use rangemap::RangeSet;
use serde::{Deserialize, Serialize};
#[cfg(any(
    target_os = "linux",
    target_vendor = "apple",
    all(target_arch = "aarch64", target_os = "android")
))]
use std::io;
use std::{collections::BTreeMap, ffi::c_void};

use crate::asan::errors::{AsanError, AsanErrors};

/// An allocator wrapper with binary-only address sanitization
#[derive(Debug)]
#[allow(missing_docs)]
pub struct Allocator {
    #[allow(dead_code)]
    options: FuzzerOptions,
    page_size: usize,
    shadow_offset: usize,
    shadow_bit: usize,
    pre_allocated_shadow: bool,
    allocations: HashMap<usize, AllocationMetadata>,
    shadow_pages: RangeSet<usize>,
    allocation_queue: BTreeMap<usize, Vec<AllocationMetadata>>,
    largest_allocation: usize,
    total_allocation_size: usize,
    base_mapping_addr: usize,
    current_mapping_addr: usize,
}

#[cfg(target_vendor = "apple")]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANON;
#[cfg(not(target_vendor = "apple"))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANONYMOUS;

macro_rules! map_to_shadow {
    ($self:expr, $address:expr) => {
        $self.shadow_offset + (($address >> 3) & ((1 << ($self.shadow_bit + 1)) - 1))
    };
}

/// Metadata for an allocation
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct AllocationMetadata {
    pub address: usize,
    pub size: usize,
    pub actual_size: usize,
    pub allocation_site_backtrace: Option<Backtrace>,
    pub release_site_backtrace: Option<Backtrace>,
    pub freed: bool,
    pub is_malloc_zero: bool,
}

impl Allocator {
    /// Creates a new [`Allocator`] (not supported on this platform!)
    #[cfg(not(any(
        target_os = "linux",
        target_vendor = "apple",
        all(target_arch = "aarch64", target_os = "android")
    )))]
    #[must_use]
    pub fn new(_: FuzzerOptions) -> Self {
        todo!("Shadow region not yet supported for this platform!");
    }

    /// Creates a new [`Allocator`]
    #[cfg(any(
        target_os = "linux",
        target_vendor = "apple",
        all(target_arch = "aarch64", target_os = "android")
    ))]
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn new(options: FuzzerOptions) -> Self {
        let ret = unsafe { sysconf(_SC_PAGESIZE) };
        assert!(
            ret >= 0,
            "Failed to read pagesize {:?}",
            io::Error::last_os_error()
        );

        #[allow(clippy::cast_sign_loss)]
        let page_size = ret as usize;
        // probe to find a usable shadow bit:
        let mut shadow_bit = 0;

        let mut occupied_ranges: Vec<(usize, usize)> = vec![];
        // max(userspace address) this is usually 0x8_0000_0000_0000 - 1 on x64 linux.
        let mut userspace_max: usize = 0;

        // Enumerate memory ranges that are already occupied.
        for prot in [
            PageProtection::Read,
            PageProtection::Write,
            PageProtection::Execute,
        ] {
            RangeDetails::enumerate_with_prot(prot, &mut |details| {
                let start = details.memory_range().base_address().0 as usize;
                let end = start + details.memory_range().size();
                occupied_ranges.push((start, end));
                // println!("{:x} {:x}", start, end);
                let base: usize = 2;
                // On x64, if end > 2**48, then that's in vsyscall or something.
                #[cfg(target_arch = "x86_64")]
                if end <= base.pow(48) && end > userspace_max {
                    userspace_max = end;
                }

                // On x64, if end > 2**52, then range is not in userspace
                #[cfg(target_arch = "aarch64")]
                if end <= base.pow(52) {
                    if end > userspace_max {
                        userspace_max = end;
                    }
                }

                true
            });
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
            for try_shadow_bit in &[maxbit - 4, maxbit - 3, maxbit - 2] {
                let addr: usize = 1 << try_shadow_bit;
                let shadow_start = addr;
                let shadow_end = addr + addr + addr;

                // check if the proposed shadow bit overlaps with occupied ranges.
                for (start, end) in &occupied_ranges {
                    if (shadow_start <= *end) && (*start <= shadow_end) {
                        // println!("{:x} {:x}, {:x} {:x}",shadow_start,shadow_end,start,end);
                        println!("shadow_bit {:x} is not suitable", try_shadow_bit);
                        break;
                    }
                }

                if unsafe {
                    mmap(
                        addr as *mut c_void,
                        page_size,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        MapFlags::MAP_PRIVATE
                            | ANONYMOUS_FLAG
                            | MapFlags::MAP_FIXED
                            | MapFlags::MAP_NORESERVE,
                        -1,
                        0,
                    )
                }
                .is_ok()
                {
                    shadow_bit = (*try_shadow_bit).try_into().unwrap();
                    break;
                }
            }
        }

        println!("shadow_bit {:x} is suitable", shadow_bit);
        assert!(shadow_bit != 0);
        // attempt to pre-map the entire shadow-memory space

        let addr: usize = 1 << shadow_bit;
        let pre_allocated_shadow = unsafe {
            mmap(
                addr as *mut c_void,
                addr + addr,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                ANONYMOUS_FLAG
                    | MapFlags::MAP_FIXED
                    | MapFlags::MAP_PRIVATE
                    | MapFlags::MAP_NORESERVE,
                -1,
                0,
            )
        }
        .is_ok();

        Self {
            options,
            page_size,
            pre_allocated_shadow,
            shadow_offset: 1 << shadow_bit,
            shadow_bit,
            allocations: HashMap::new(),
            shadow_pages: RangeSet::new(),
            allocation_queue: BTreeMap::new(),
            largest_allocation: 0,
            total_allocation_size: 0,
            base_mapping_addr: addr + addr + addr,
            current_mapping_addr: addr + addr + addr,
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
            // println!("zero-sized allocation!");
            is_malloc_zero = true;
            16
        } else {
            size
        };
        if size > self.options.max_allocation {
            #[allow(clippy::manual_assert)]
            if self.options.max_allocation_panics {
                panic!("ASAN: Allocation is too large: 0x{:x}", size);
            }

            return std::ptr::null_mut();
        }
        let rounded_up_size = self.round_up_to_page(size) + 2 * self.page_size;

        if self.total_allocation_size + rounded_up_size > self.options.max_total_allocation {
            return std::ptr::null_mut();
        }
        self.total_allocation_size += rounded_up_size;

        let metadata = if let Some(mut metadata) = self.find_smallest_fit(rounded_up_size) {
            //println!("reusing allocation at {:x}, (actual mapping starts at {:x}) size {:x}", metadata.address, metadata.address - self.page_size, size);
            metadata.is_malloc_zero = is_malloc_zero;
            metadata.size = size;
            if self.options.allocation_backtraces {
                metadata.allocation_site_backtrace = Some(Backtrace::new_unresolved());
            }
            metadata
        } else {
            // println!("{:x}, {:x}", self.current_mapping_addr, rounded_up_size);
            let mapping = match mmap(
                self.current_mapping_addr as *mut c_void,
                rounded_up_size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                ANONYMOUS_FLAG
                    | MapFlags::MAP_PRIVATE
                    | MapFlags::MAP_FIXED
                    | MapFlags::MAP_NORESERVE,
                -1,
                0,
            ) {
                Ok(mapping) => mapping as usize,
                Err(err) => {
                    println!("An error occurred while mapping memory: {:?}", err);
                    return std::ptr::null_mut();
                }
            };
            self.current_mapping_addr += rounded_up_size;

            self.map_shadow_for_region(mapping, mapping + rounded_up_size, false);

            let mut metadata = AllocationMetadata {
                address: mapping,
                size,
                actual_size: rounded_up_size,
                ..AllocationMetadata::default()
            };
            if self.options.allocation_backtraces {
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

        self.allocations
            .insert(metadata.address + self.page_size, metadata);
        //println!("serving address: {:?}, size: {:x}", address, size);
        address
    }

    /// Releases the allocation at the given address.
    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn release(&mut self, ptr: *mut c_void) {
        //println!("freeing address: {:?}", ptr);
        let mut metadata = if let Some(metadata) = self.allocations.get_mut(&(ptr as usize)) {
            metadata
        } else {
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
        if self.options.allocation_backtraces {
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
        for metadata in metadatas {
            let new_offset = if hint_base == metadata.address {
                (ptr as i64 - metadata.address as i64).abs()
            } else {
                std::cmp::min(
                    offset_to_closest,
                    (ptr as i64 - metadata.address as i64).abs(),
                )
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
                    "Attempted to get_usable_size on a pointer ({:?}) which was not allocated!",
                    ptr
                );
            }
        }
    }

    fn unpoison(start: usize, size: usize) {
        // println!("unpoisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            // println!("memset: {:?}", start as *mut c_void);
            memset(start as *mut c_void, 0xff, size / 8);

            let remainder = size % 8;
            if remainder > 0 {
                // println!("remainder: {:x}, offset: {:x}", remainder, start + size / 8);
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
        // println!("poisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            // println!("memset: {:?}", start as *mut c_void);
            memset(start as *mut c_void, 0x00, size / 8);

            let remainder = size % 8;
            if remainder > 0 {
                // println!("remainder: {:x}, offset: {:x}", remainder, start + size / 8);
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
        //println!("start: {:x}, end {:x}, size {:x}", start, end, end - start);

        let shadow_mapping_start = map_to_shadow!(self, start);

        if !self.pre_allocated_shadow {
            let shadow_start = self.round_down_to_page(shadow_mapping_start);
            let shadow_end =
                self.round_up_to_page((end - start) / 8) + self.page_size + shadow_start;
            for range in self.shadow_pages.gaps(&(shadow_start..shadow_end)) {
                /*
                println!(
                    "range: {:x}-{:x}, pagesize: {}",
                    range.start, range.end, self.page_size
                );
                */
                unsafe {
                    mmap(
                        range.start as *mut c_void,
                        range.end - range.start,
                        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                        ANONYMOUS_FLAG | MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
                        -1,
                        0,
                    )
                    .expect("An error occurred while mapping shadow memory");
                }
            }

            self.shadow_pages.insert(shadow_start..shadow_end);
        }

        //println!("shadow_mapping_start: {:x}, shadow_size: {:x}", shadow_mapping_start, (end - start) / 8);
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
                if self.pre_allocated_shadow && start == 1 << self.shadow_bit {
                    return true;
                }
                self.map_shadow_for_region(start, end, true);
            }
            true
        });
    }
}
