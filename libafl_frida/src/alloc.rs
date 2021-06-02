use hashbrown::HashMap;
#[cfg(any(target_os = "linux", target_os = "android"))]
use libafl::bolts::os::walk_self_maps;
use nix::{
    libc::memset,
    sys::mman::{mmap, MapFlags, ProtFlags},
};

use backtrace::Backtrace;
#[cfg(unix)]
use libc::{sysconf, _SC_PAGESIZE};
use rangemap::RangeSet;
use serde::{Deserialize, Serialize};
use std::{ffi::c_void, io};

use crate::{
    asan_errors::{AsanError, AsanErrors},
    FridaOptions,
};

pub(crate) struct Allocator {
    options: FridaOptions,
    page_size: usize,
    shadow_offset: usize,
    shadow_bit: usize,
    pre_allocated_shadow: bool,
    allocations: HashMap<usize, AllocationMetadata>,
    shadow_pages: RangeSet<usize>,
    allocation_queue: HashMap<usize, Vec<AllocationMetadata>>,
    largest_allocation: usize,
    base_mapping_addr: usize,
    current_mapping_addr: usize,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANON;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANONYMOUS;

macro_rules! map_to_shadow {
    ($self:expr, $address:expr) => {
        (($address >> 3) + $self.shadow_offset) & ((1 << ($self.shadow_bit + 1)) - 1)
    };
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct AllocationMetadata {
    pub address: usize,
    pub size: usize,
    pub actual_size: usize,
    pub allocation_site_backtrace: Option<Backtrace>,
    pub release_site_backtrace: Option<Backtrace>,
    pub freed: bool,
    pub is_malloc_zero: bool,
}

impl Allocator {
    pub fn new(options: FridaOptions) -> Self {
        let ret = unsafe { sysconf(_SC_PAGESIZE) };
        if ret < 0 {
            panic!("Failed to read pagesize {:?}", io::Error::last_os_error());
        }
        #[allow(clippy::cast_sign_loss)]
        let page_size = ret as usize;
        // probe to find a usable shadow bit:
        let mut shadow_bit: usize = 0;


        for try_shadow_bit in &[46usize, 36usize] {
            let addr: usize = 1 << try_shadow_bit;
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
                shadow_bit = *try_shadow_bit;
                break;
            }
        }
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
            allocation_queue: HashMap::new(),
            largest_allocation: 0,
            base_mapping_addr: addr + addr + addr,
            current_mapping_addr: addr + addr + addr,
        }
    }

    /// Retreive the shadow bit used by this allocator.
    pub fn shadow_bit(&self) -> u32 {
        self.shadow_bit as u32
    }

    #[inline]
    fn round_up_to_page(&self, size: usize) -> usize {
        ((size + self.page_size) / self.page_size) * self.page_size
    }

    #[inline]
    fn round_down_to_page(&self, value: usize) -> usize {
        (value / self.page_size) * self.page_size
    }

    fn find_smallest_fit(&mut self, size: usize) -> Option<AllocationMetadata> {
        let mut current_size = size;
        while current_size <= self.largest_allocation {
            if self.allocation_queue.contains_key(&current_size) {
                if let Some(metadata) = self.allocation_queue.entry(current_size).or_default().pop()
                {
                    return Some(metadata);
                }
            }
            current_size *= 2;
        }
        None
    }

    pub unsafe fn alloc(&mut self, size: usize, _alignment: usize) -> *mut c_void {
        let mut is_malloc_zero = false;
        let size = if size == 0 {
            println!("zero-sized allocation!");
            is_malloc_zero = true;
            16
        } else {
            size
        };
        if size > (1 << 30) {
            panic!("Allocation is too large: 0x{:x}", size);
        }
        let rounded_up_size = self.round_up_to_page(size) + 2 * self.page_size;

        let metadata = if let Some(mut metadata) = self.find_smallest_fit(rounded_up_size) {
            //println!("reusing allocation at {:x}, (actual mapping starts at {:x}) size {:x}", metadata.address, metadata.address - self.page_size, size);
            metadata.is_malloc_zero = is_malloc_zero;
            metadata.size = size;
            if self.options.enable_asan_allocation_backtraces {
                metadata.allocation_site_backtrace = Some(Backtrace::new_unresolved());
            }
            metadata
        } else {
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

            if self.options.enable_asan_allocation_backtraces {
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

    pub unsafe fn release(&mut self, ptr: *mut c_void) {
        let mut metadata = if let Some(metadata) = self.allocations.get_mut(&(ptr as usize)) {
            metadata
        } else {
            if !ptr.is_null() {
                AsanErrors::get_mut().report_error(
                    AsanError::UnallocatedFree((ptr as usize, Backtrace::new())),
                    None,
                );
            }
            return;
        };

        if metadata.freed {
            AsanErrors::get_mut().report_error(
                AsanError::DoubleFree((ptr as usize, metadata.clone(), Backtrace::new())),
                None,
            );
        }
        let shadow_mapping_start = map_to_shadow!(self, ptr as usize);

        metadata.freed = true;
        if self.options.enable_asan_allocation_backtraces {
            metadata.release_site_backtrace = Some(Backtrace::new_unresolved());
        }

        // poison the shadow memory for the allocation
        Self::poison(shadow_mapping_start, metadata.size);
    }

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

    pub fn reset(&mut self) {
        for (address, mut allocation) in self.allocations.drain() {
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
    }

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
        //println!("unpoisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            //println!("memset: {:?}", start as *mut c_void);
            memset(start as *mut c_void, 0xff, size / 8);

            let remainder = size % 8;
            if remainder > 0 {
                //println!("remainder: {:x}, offset: {:x}", remainder, start + size / 8);
                memset(
                    (start + size / 8) as *mut c_void,
                    (0xff << (8 - remainder)) & 0xff,
                    1,
                );
            }
        }
    }

    pub fn poison(start: usize, size: usize) {
        //println!("poisoning {:x} for {:x}", start, size / 8 + 1);
        unsafe {
            //println!("memset: {:?}", start as *mut c_void);
            memset(start as *mut c_void, 0x00, size / 8);

            let remainder = size % 8;
            if remainder > 0 {
                //println!("remainder: {:x}, offset: {:x}", remainder, start + size / 8);
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
                //println!("range: {:x}-{:x}, pagesize: {}", range.start, range.end, self.page_size);
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

    pub fn map_to_shadow(&self, start: usize) -> usize {
        map_to_shadow!(self, start)
    }

    #[inline]
    pub fn is_managed(&self, ptr: *mut c_void) -> bool {
        //self.allocations.contains_key(&(ptr as usize))
        self.base_mapping_addr <= ptr as usize && (ptr as usize) < self.current_mapping_addr
    }

    pub fn check_for_leaks(&self) {
        for metadata in self.allocations.values() {
            if !metadata.freed {
                AsanErrors::get_mut()
                    .report_error(AsanError::Leak((metadata.address, metadata.clone())), None);
            }
        }
    }

    /// Unpoison all the memory that is currently mapped with read/write permissions.
    pub fn unpoison_all_existing_memory(&mut self) {
        walk_self_maps(&mut |start, end, permissions, _path| {
            if permissions.as_bytes()[0] == b'r' || permissions.as_bytes()[1] == b'w' {
                if self.pre_allocated_shadow && start == 1 << self.shadow_bit {
                    return false;
                }
                self.map_shadow_for_region(start, end, true);
            }
            false
        });
    }
}
