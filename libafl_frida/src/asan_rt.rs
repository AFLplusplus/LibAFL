use hashbrown::HashMap;
use nix::{
    libc::{memmove, memset},
    sys::mman::{mmap, MapFlags, ProtFlags},
};

use backtrace::Backtrace;
use capstone::{arch::BuildsCapstone, Capstone};
use color_backtrace::{default_output_stream, BacktracePrinter};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use gothook::GotHookLibrary;
use libc::{pthread_atfork, sysconf, _SC_PAGESIZE};
use rangemap::RangeSet;
use regex::Regex;
use std::{
    cell::RefCell,
    cell::RefMut,
    ffi::c_void,
    fs::File,
    io::{BufRead, BufReader, Write},
    pin::Pin,
};
use termcolor::{Color, ColorSpec, WriteColor};

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
    regs: [usize; 32],
    blob_check_mem_byte: Option<Box<[u8]>>,
    blob_check_mem_halfword: Option<Box<[u8]>>,
    blob_check_mem_dword: Option<Box<[u8]>>,
    blob_check_mem_qword: Option<Box<[u8]>>,
    blob_check_mem_16bytes: Option<Box<[u8]>>,
    stalked_addresses: HashMap<usize, usize>,
}

impl AsanRuntime {
    pub fn new() -> AsanRuntime {
        let allocator = Allocator::get();
        allocator.init();

        Self {
            regs: [0; 32],
            blob_check_mem_byte: None,
            blob_check_mem_halfword: None,
            blob_check_mem_dword: None,
            blob_check_mem_qword: None,
            blob_check_mem_16bytes: None,
            stalked_addresses: HashMap::new(),
        }
    }
    /// Initialize the runtime so that it is read for action. Take care not to move the runtime
    /// instance after this function has been called, as the generated blobs would become
    /// invalid!
    pub fn init(&mut self, module_name: &str) {
        // workaround frida's frida-gum-allocate-near bug:
        unsafe {
            for _ in 0..50 {
                mmap(std::ptr::null_mut(), 128 * 1024, ProtFlags::PROT_NONE, MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE, -1, 0).expect("Failed to map dummy regions for frida workaround");
            }
        }


        self.generate_instrumentation_blobs();
        self.unpoison_all_existing_memory();
        self.hook_library(module_name);
    }

    /// Add a stalked address to real address mapping.
    //#[inline]
    pub fn add_stalked_address(&mut self, stalked: usize, real: usize) {
        self.stalked_addresses.insert(stalked, real);
    }

    /// Unpoison all the memory that is currently mapped with read/write permissions.
    fn unpoison_all_existing_memory(&self) {
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
    fn hook_library(&mut self, path: &str) {
        let target_lib = GotHookLibrary::new(path, false);

        // shadow the library itself, allowing all accesses
        Allocator::get().map_shadow_for_region(target_lib.start(), target_lib.end(), true);

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

    extern "C" fn handle_trap(&mut self) {
        let mut actual_pc = self.regs[31] + 32 + 4;
        actual_pc = match self.stalked_addresses.get(&actual_pc) {
            Some(addr) => *addr,
            _ => actual_pc,
        };

        let mut cs = Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .build()
            .unwrap();
        cs.set_skipdata(true).expect("failed to set skipdata");

        let mut out_stream = default_output_stream();
        let output = out_stream.as_mut();

        writeln!(output, "{:━^80}", " Memory error detected! ").unwrap();

        for reg in 0..=30 {
            write!(output, "x{:02}: 0x{:016x} ", reg, self.regs[reg]).unwrap();
            if reg % 4 == 3 {
                writeln!(output, "").unwrap();
            }
        }
        writeln!(output, "pc : 0x{:016x} ", actual_pc).unwrap();

        let start_pc = actual_pc - 4 * 5;
        for insn in cs
            .disasm_count(
                unsafe { std::slice::from_raw_parts(start_pc as *mut u8, 4 * 11) },
                start_pc as u64,
                11,
            )
            .expect("failed to disassemble instructions")
            .iter()
        {
            if insn.address() as usize == actual_pc {
                output
                    .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                    .unwrap();
                writeln!(output, "\t => {}", insn).unwrap();
                output.reset().unwrap();
            } else {
                writeln!(output, "\t    {}", insn).unwrap();
            }
        }
        BacktracePrinter::new()
           .add_frame_filter(Box::new(|frames| {
              frames.retain(|x| matches!(&x.name, Some(n) if !n.starts_with("libafl_frida::asan_rt::AsanRuntime::handle_trap")))
           }))
           .print_trace(&Backtrace::new(), output)
          .unwrap();

        panic!("Crashing!");
    }

    /// Generate the instrumentation blobs for the current arch.
    fn generate_instrumentation_blobs(&mut self) {
        macro_rules! shadow_check {
            ($ops:ident, $bit:expr) => {dynasm!($ops
                ; .arch aarch64
                ; mov x1, #1
                ; add x1, xzr, x1, lsl #36
                ; add x1, x1, x0, lsr #3
                ; ldrh w1, [x1, #0]
                ; and x0, x0, #7
                ; rev16 w1, w1
                ; rbit w1, w1
                ; lsr x1, x1, #16
                ; lsr x1, x1, x0
                ; tbnz x1, #$bit, >done
                //; brk #$bit
                ; ldr x0, >self_regs_addr
                ; stp x2, x3, [x0, #0x10]
                ; stp x4, x5, [x0, #0x20]
                ; stp x6, x7, [x0, #0x30]
                ; stp x8, x9, [x0, #0x40]
                ; stp x10, x11, [x0, #0x50]
                ; stp x12, x13, [x0, #0x60]
                ; stp x14, x15, [x0, #0x70]
                ; stp x16, x17, [x0, #0x80]
                ; stp x18, x19, [x0, #0x90]
                ; stp x20, x21, [x0, #0xa0]
                ; stp x22, x23, [x0, #0xb0]
                ; stp x24, x25, [x0, #0xc0]
                ; stp x26, x27, [x0, #0xd0]
                ; stp x28, x29, [x0, #0xe0]
                ; stp x30, xzr, [x0, #0xf0]
                ; mov x3, x0
                ; ldp x0, x1, [sp], #144
                ; stp x0, x1, [x3]
                ; ldr x0, >self_addr
                ; ldr x1, >trap_func
                ; bl >here
                ; here:
                ; str x30, [x3, 0xf8]
                ; ldr x30, [x3, 0xf0]
                ; br x1
                ; self_addr:
                ; .qword self as *mut _  as *mut c_void as i64
                ; self_regs_addr:
                ; .qword &mut self.regs as *mut _ as *mut c_void as i64
                ; trap_func:
                ; .qword AsanRuntime::handle_trap as *mut c_void as i64
                ; done:
            );};
        }

        let mut ops_check_mem_byte =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check!(ops_check_mem_byte, 0);
        self.blob_check_mem_byte = Some(ops_check_mem_byte.finalize().unwrap().into_boxed_slice() );

        let mut ops_check_mem_halfword =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check!(ops_check_mem_halfword, 1);
        self.blob_check_mem_halfword = Some(ops_check_mem_halfword.finalize().unwrap().into_boxed_slice());

        let mut ops_check_mem_dword =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check!(ops_check_mem_dword, 2);
        self.blob_check_mem_dword = Some(ops_check_mem_dword.finalize().unwrap().into_boxed_slice());

        let mut ops_check_mem_qword =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check!(ops_check_mem_qword, 3);
        self.blob_check_mem_qword = Some(ops_check_mem_qword.finalize().unwrap().into_boxed_slice());

        let mut ops_check_mem_16bytes =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check!(ops_check_mem_16bytes, 4);
        self.blob_check_mem_16bytes = Some(ops_check_mem_16bytes.finalize().unwrap().into_boxed_slice());
    }

    /// Get the blob which checks a byte access
    #[inline]
    pub fn blob_check_mem_byte(&self) -> &Box<[u8]> {
        self.blob_check_mem_byte.as_ref().unwrap()
    }

    /// Get the blob which checks a halfword access
    #[inline]
    pub fn blob_check_mem_halfword(&self) -> &Box<[u8]> {
        self.blob_check_mem_halfword.as_ref().unwrap()
    }

    /// Get the blob which checks a dword access
    #[inline]
    pub fn blob_check_mem_dword(&self) -> &Box<[u8]> {
        self.blob_check_mem_dword.as_ref().unwrap()
    }

    /// Get the blob which checks a qword access
    #[inline]
    pub fn blob_check_mem_qword(&self) -> &Box<[u8]> {
       self.blob_check_mem_qword.as_ref().unwrap()
    }

    /// Get the blob which checks a 16 byte access
    #[inline]
    pub fn blob_check_mem_16bytes(&self) -> &Box<[u8]> {
        self.blob_check_mem_16bytes.as_ref().unwrap()
    }
}
