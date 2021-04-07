use hashbrown::HashMap;
use nix::{
    libc::{memmove, memset},
    sys::mman::{mmap, mprotect, msync, MapFlags, MsFlags, ProtFlags},
};

use libc::{pthread_atfork, sysconf, _SC_PAGESIZE};
use std::{
    cell::RefCell,
    cell::RefMut,
    ffi::c_void,
    fs::File,
    io::{BufRead, BufReader},
};

use libloading::Library;
use regex::Regex;

use rangemap::RangeSet;

static mut ALLOCATOR_SINGLETON: Option<RefCell<Allocator>> = None;

struct Allocator {
    page_size: usize,
    shadow_offset: usize,
    allocations: HashMap<usize, usize>,
    shadow_pages: RangeSet<usize>,
}

impl Allocator {
    pub fn new() -> Self {
        Self {
            page_size: unsafe { sysconf(_SC_PAGESIZE) as usize },
            shadow_offset: 1 << 36,
            allocations: HashMap::new(),
            shadow_pages: RangeSet::new(),
        }
    }

    pub fn get() -> RefMut<'static, Allocator> {
        unsafe {
            if ALLOCATOR_SINGLETON.as_mut().is_none() {
                ALLOCATOR_SINGLETON = Some(RefCell::new(Allocator::new()));
            }

            // we need to loop in case there is a race between threads at init time.
            //loop {
            //if let Ok(allocref) = ALLOCATOR_SINGLETON.as_mut().unwrap().try_borrow_mut() {
            //return allocref;
            //}
            //}
            ALLOCATOR_SINGLETON
                .as_mut()
                .unwrap()
                .try_borrow_mut()
                .unwrap()
        }
    }

    pub fn init(&self) {
        unsafe extern "C" fn atfork() {
            ALLOCATOR_SINGLETON = None;
            Allocator::get();
        }
        unsafe {
            pthread_atfork(None, None, Some(atfork));
        }
    }

    #[inline]
    fn round_up_to_page(&self, size: usize) -> usize {
        ((size + self.page_size) / self.page_size) * self.page_size
    }

    #[inline]
    fn round_down_to_page(&self, value: usize) -> usize {
        (value / self.page_size) * self.page_size
    }

    pub unsafe fn alloc(&mut self, size: usize, _alignment: usize) -> *mut c_void {
        let rounded_up_size = self.round_up_to_page(size);

        let mapping = match mmap(
            std::ptr::null_mut(),
            rounded_up_size + 2 * self.page_size,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
            -1,
            0,
        ) {
            Ok(mapping) => mapping as usize,
            Err(err) => {
                println!("An error occurred while mapping memory: {:?}", err);
                return std::ptr::null_mut();
            }
        };

        let (shadow_mapping_start, _shadow_mapping_size) = self.map_shadow_for_region(
            mapping,
            mapping + rounded_up_size + 2 * self.page_size,
            false,
        );

        // unpoison the shadow memory for the allocation itself
        self.unpoison(shadow_mapping_start + self.page_size / 8, size);

        self.allocations.insert(mapping + self.page_size, size);

        (mapping + self.page_size) as *mut c_void
    }

    pub unsafe fn release(&self, ptr: *mut c_void) {
        let size = match self.allocations.get(&(ptr as usize)) {
            Some(size) => size,
            None => return,
        };
        let shadow_mapping_start = (ptr as usize >> 3) + self.shadow_offset;

        // poison the shadow memory for the allocation
        //println!("poisoning {:x} for {:x}", shadow_mapping_start, size / 8 + 1);
        memset(shadow_mapping_start as *mut c_void, 0x00, size / 8);
        let remainder = size % 8;
        if remainder > 0 {
            memset((shadow_mapping_start + size / 8) as *mut c_void, 0x00, 1);
        }
    }

    pub fn get_usable_size(&self, ptr: *mut c_void) -> usize {
        *self.allocations.get(&(ptr as usize)).unwrap()
    }

    fn unpoison(&self, start: usize, size: usize) {
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

    /// Map shadow memory for a region, and optionally unpoison it
    pub fn map_shadow_for_region(
        &mut self,
        start: usize,
        end: usize,
        unpoison: bool,
    ) -> (usize, usize) {
        //println!("start: {:x}, end {:x}, size {:x}", start, end, end - start);

        let shadow_mapping_start = (start >> 3) + self.shadow_offset;
        let shadow_start = self.round_down_to_page(shadow_mapping_start);
        let shadow_end = self.round_up_to_page((end - start) / 8) + self.page_size + shadow_start;

        for range in self.shadow_pages.gaps(&(shadow_start..shadow_end)) {
            //println!("mapping: {:x} - {:x}", mapping_start * self.page_size, (mapping_end + 1) * self.page_size);
            unsafe {
                mmap(
                    range.start as *mut c_void,
                    range.end - range.start,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE,
                    -1,
                    0,
                )
                .expect("An error occurred while mapping shadow memory");
            }
        }

        self.shadow_pages.insert(shadow_start..shadow_end);

        //println!("shadow_mapping_start: {:x}, shadow_size: {:x}", shadow_mapping_start, (end - start) / 8);
        if unpoison {
            self.unpoison(shadow_mapping_start, end - start);
        }

        (shadow_mapping_start, (end - start) / 8)
    }
}

/// Hook for malloc.
pub extern "C" fn asan_malloc(size: usize) -> *mut c_void {
    unsafe { Allocator::get().alloc(size, 0x8) }
}

/// Hook for pvalloc
pub extern "C" fn asan_pvalloc(size: usize) -> *mut c_void {
    unsafe { Allocator::get().alloc(size, 0x8) }
}

/// Hook for valloc
pub extern "C" fn asan_valloc(size: usize) -> *mut c_void {
    unsafe { Allocator::get().alloc(size, 0x8) }
}

/// Hook for calloc
pub extern "C" fn asan_calloc(nmemb: usize, size: usize) -> *mut c_void {
    unsafe { Allocator::get().alloc(size * nmemb, 0x8) }
}

/// Hook for realloc
///
/// # Safety
/// This function is inherently unsafe, as it takes a raw pointer
pub unsafe extern "C" fn asan_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let mut allocator = Allocator::get();
    let ret = allocator.alloc(size, 0x8);
    if ptr != std::ptr::null_mut() {
        memmove(ret, ptr, allocator.get_usable_size(ptr));
    }
    allocator.release(ptr);
    ret
}

/// Hook for free
///
/// # Safety
/// This function is inherently unsafe, as it takes a raw pointer
pub unsafe extern "C" fn asan_free(ptr: *mut c_void) {
    if ptr != std::ptr::null_mut() {
        Allocator::get().release(ptr);
    }
}

/// Hook for malloc_usable_size
///
/// # Safety
/// This function is inherently unsafe, as it takes a raw pointer
pub unsafe extern "C" fn asan_malloc_usable_size(ptr: *mut c_void) -> usize {
    Allocator::get().get_usable_size(ptr)
}

/// Hook for memalign
pub extern "C" fn asan_memalign(size: usize, alignment: usize) -> *mut c_void {
    unsafe { Allocator::get().alloc(size, alignment) }
}

/// Hook for posix_memalign
///
/// # Safety
/// This function is inherently unsafe, as it takes a raw pointer
pub unsafe extern "C" fn asan_posix_memalign(
    pptr: *mut *mut c_void,
    size: usize,
    alignment: usize,
) -> i32 {
    *pptr = Allocator::get().alloc(size, alignment);
    0
}

/// Hook for mallinfo
pub extern "C" fn asan_mallinfo() -> *mut c_void {
    std::ptr::null_mut()
}

/// Allows one to walk the mappings in /proc/self/maps, caling a callback function for each
/// mapping.
/// If the callback returns true, we stop the walk.
fn walk_self_maps(visitor: &mut dyn FnMut(usize, usize, String, String) -> bool) {
    let re = Regex::new(r"^(?P<start>[0-9a-f]{8,16})-(?P<end>[0-9a-f]{8,16}) (?P<perm>[-rwxp]{4}) (?P<offset>[0-9a-f]{8}) [0-9a-f]+:[0-9a-f]+ [0-9]+\s+(?P<path>.*)$")
        .unwrap();

    let mapsfile = File::open("/proc/self/maps").expect("Unable to open /proc/self/maps");

    for line in BufReader::new(mapsfile).lines() {
        let line = line.unwrap();
        if let Some(caps) = re.captures(&line) {
            if visitor(
                usize::from_str_radix(caps.name("start").unwrap().as_str(), 16).unwrap(),
                usize::from_str_radix(caps.name("end").unwrap().as_str(), 16).unwrap(),
                caps.name("perm").unwrap().as_str().to_string(),
                caps.name("path").unwrap().as_str().to_string(),
            ) {
                break;
            };
        }
    }
}

/// Get the current thread's TLS address
extern "C" {
    fn get_tls_ptr() -> *const c_void;
}

/// Get the start and end address of the mapping containing a particular address
fn mapping_containing(address: *const c_void) -> (usize, usize) {
    let mut result = (0, 0);
    walk_self_maps(&mut |start, end, _permissions, _path| {
        if start <= (address as usize) && (address as usize) < end {
            result = (start, end);
            true
        } else {
            false
        }
    });

    result
}

/// Get the start and end address of the mapping containing a particular address
fn mapping_for_library(libpath: &str) -> (usize, usize) {
    let mut libstart = 0;
    let mut libend = 0;
    walk_self_maps(&mut |start, end, _permissions, path| {
        if libpath == path {
            if libstart == 0 {
                libstart = start;
            }

            libend = end;
        }
        false
    });

    (libstart, libend)
}

pub struct AsanRuntime {
    //allocator: Allocator,
}

impl AsanRuntime {
    pub fn new() -> Self {
        let allocator = Allocator::get();
        allocator.init();

        Self {
            //allocator: *allocator,
        }
    }

    /// Unpoison all the memory that is currently mapped with read/write permissions.
    pub fn unpoison_all_existing_memory(&self) {
        walk_self_maps(&mut |start, end, _permissions, _path| {
            //if permissions.as_bytes()[0] == b'r' || permissions.as_bytes()[1] == b'w' {
            Allocator::get().map_shadow_for_region(start, end, true);
            //}
            false
        });
    }

    /// Register the current thread with the runtime, implementing shadow memory for its stack and
    /// tls mappings.
    pub fn register_thread(&self) {
        let mut allocator = Allocator::get();
        let (stack_start, stack_end) = Self::current_stack();
        allocator.map_shadow_for_region(stack_start, stack_end, true);

        let (tls_start, tls_end) = Self::current_tls();
        allocator.map_shadow_for_region(tls_start, tls_end, true);
        println!(
            "registering thread with stack {:x}:{:x} and tls {:x}:{:x}",
            stack_start as usize, stack_end as usize, tls_start as usize, tls_end as usize
        );
    }

    /// Determine the stack start, end for the currently running thread
    fn current_stack() -> (usize, usize) {
        let stack_var = 0xeadbeef;
        let stack_address = &stack_var as *const _ as *const c_void;

        mapping_containing(stack_address)
    }

    /// Determine the tls start, end for the currently running thread
    fn current_tls() -> (usize, usize) {
        let tls_address = unsafe { get_tls_ptr() };

        mapping_containing(tls_address)
    }

    /// Locate the target library and hook it's memory allocation functions
    pub fn hook_library(&mut self, path: &str) {
        let target_lib = HookerTargetLibrary::new(path, false);

        // shadow the library itself, allowing all accesses
        Allocator::get().map_shadow_for_region(target_lib.start, target_lib.end, true);

        // Hook all the memory allocator functions
        target_lib.hook_function("malloc", asan_malloc as *const c_void);
        target_lib.hook_function("calloc", asan_calloc as *const c_void);
        target_lib.hook_function("pvalloc", asan_pvalloc as *const c_void);
        target_lib.hook_function("valloc", asan_valloc as *const c_void);
        target_lib.hook_function("realloc", asan_realloc as *const c_void);
        target_lib.hook_function("free", asan_free as *const c_void);
        target_lib.hook_function("memalign", asan_memalign as *const c_void);
        target_lib.hook_function("posix_memalign", asan_posix_memalign as *const c_void);
        target_lib.hook_function(
            "malloc_usable_size",
            asan_malloc_usable_size as *const c_void,
        );
    }
}
struct HookerTargetLibrary<'a> {
    path: &'a str,
    start: usize,
    end: usize,
    file_in_memory: Box<&'a [u8]>,
    elf: goblin::elf::Elf<'a>,
}

impl<'a> HookerTargetLibrary<'a> {
    /// Create a new library to be hooked from a path. If the load boolean is true, the library will first be
    /// loaded.
    pub fn new(path: &'a str, load: bool) -> Self {
        println!("Path is {:?}", path);
        let library = if load {
            Some(unsafe { Library::new(path) })
        } else {
            None
        };

        println!("library: {:?}", library);

        let (start, end) = mapping_for_library(path);

        let file_in_memory = unsafe { std::slice::from_raw_parts(start as *const u8, end - start) };
        let mut elf = goblin::elf::Elf::lazy_parse(
            goblin::elf::Elf::parse_header(file_in_memory).expect("Failed to parse elf"),
        )
        .expect("Failed to parse elf lazily");

        let ctx = goblin::container::Ctx {
            le: scroll::Endian::Little,
            container: goblin::container::Container::Big,
        };
        elf.program_headers = goblin::elf::ProgramHeader::parse(
            &file_in_memory,
            elf.header.e_phoff as usize,
            elf.header.e_phnum as usize,
            ctx,
        )
        .expect("parse program headers");
        // because we're in memory, we need to use teh vaddr. goblin uses offsets, so we'll
        // just patch the PHDRS so that they have offsets equal to vaddr.
        for mut program_header in &mut elf.program_headers {
            program_header.p_offset = program_header.p_vaddr;
        }
        elf.dynamic =
            goblin::elf::dynamic::Dynamic::parse(&file_in_memory, &elf.program_headers, ctx)
                .expect("parse dynamic section");

        //let mut relandroid_offset = 0;
        //let mut relandroid_size = 0;

        //for dynentry in elf.dynamic.unwrap().dyns {
        //match dynentry.d_tag {
        //goblin::elf64::dynamic::DT_LOOS + 2 | goblin::elf64::dynamic::DT_LOOS + 4 => {
        //relandroid_offset = dynentry.d_val;
        //},
        //goblin::elf64::dynamic::DT_LOOS + 3 | goblin::elf64::dynamic::DT_LOOS + 5 => {
        //relandroid_size = dynentry.d_val;
        //},
        //}
        //}

        let info = &elf.dynamic.as_ref().unwrap().info;

        // second word of hash
        let chain_count = unsafe {
            std::slice::from_raw_parts((start + info.hash.unwrap() as usize + 4) as *mut u32, 1)[0]
        };

        elf.dynsyms = goblin::elf::sym::Symtab::parse(
            &file_in_memory,
            info.symtab,
            chain_count as usize,
            ctx,
        )
        .expect("parse dynsyms");
        elf.dynstrtab =
            goblin::strtab::Strtab::parse(&file_in_memory, info.strtab, info.strsz, b'\x00')
                .expect("parse dynstrtab");
        elf.pltrelocs = goblin::elf::RelocSection::parse(
            &file_in_memory,
            info.jmprel,
            info.pltrelsz,
            info.pltrel == goblin::elf64::dynamic::DT_RELA,
            ctx,
        )
        .expect("parse pltrel");
        //
        //let dynsyms = &elf.dynsyms.to_vec();
        //let gnu_hash_metadata = unsafe { std::slice::from_raw_parts((start + dynamic.info.gnu_hash.unwrap() as usize) as *mut u32, 4)};
        //let gnu_hash_size = (dynsyms.len() - gnu_hash_metadata[1] as usize) * 4 + gnu_hash_metadata[0] as usize * 4 + gnu_hash_metadata[2] as usize  * 8 + 4 * 4;
        //let gnu_hash = unsafe { goblin::elf64::gnu_hash::GnuHash::from_raw_table(
        //std::slice::from_raw_parts((start + dynamic.info.gnu_hash.unwrap() as usize) as *mut u8,  gnu_hash_size as usize),
        //dynsyms) }.expect("parse gnu_hash");

        Self {
            path,
            start,
            end,
            file_in_memory: Box::new(file_in_memory),
            elf,
        }
    }

    pub fn hook_function(&self, name: &str, newfunc: *const c_void) -> bool {
        let mut symindex: isize = -1;
        for (i, symbol) in self.elf.dynsyms.iter().enumerate() {
            if name == self.elf.dynstrtab.get(symbol.st_name).unwrap().unwrap() {
                symindex = i as isize;
                break;
            }
        }

        if symindex == -1 {
            println!("failed to find function {:?}", name);
            return false;
        }

        let mut offset: isize = -1;
        for reloc in self.elf.pltrelocs.iter() {
            if reloc.r_sym == symindex as usize {
                offset = reloc.r_offset as isize;
                break;
            }
        }

        unsafe {
            let address = self.start + offset as usize;
            let value = std::ptr::read(address as *const *const c_void);
            println!(
                "found {:?} at address {:x}, with value {:x}, replacing...",
                name, address, value as usize
            );
            mprotect(
                ((address / 0x1000) * 0x1000) as *mut c_void,
                0x1000,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
            .expect("Failed to mprotect to read/write");
            std::ptr::replace(address as *mut *const c_void, newfunc);
            mprotect(
                ((address / 0x1000) * 0x1000) as *mut c_void,
                0x1000,
                ProtFlags::PROT_READ,
            )
            .expect("Failed to mprotect back to read-only");

            let value = std::ptr::read(address as *const *const c_void);
            println!(
                "verified value set to {:x}, expected {:x}",
                value as usize, newfunc as usize
            );

            value == newfunc
        }
    }
}
