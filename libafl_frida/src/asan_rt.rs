/*!
The frida address sanitizer runtime provides address sanitization.
When executing in `ASAN`, each memory access will get checked, using frida stalker under the hood.
The runtime can report memory errors that occurred during execution,
even if the target would not have crashed under normal conditions.
this helps finding mem errors early.
*/

#[cfg(target_arch = "aarch64")]
use frida_gum::NativePointer;
use frida_gum::RangeDetails;
use hashbrown::HashMap;
use nix::sys::mman::mprotect;

use nix::sys::mman::{mmap, MapFlags, ProtFlags};

use nix::libc::memset;

use backtrace::Backtrace;

#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{arm64::Arm64OperandType, ArchOperand::Arm64Operand, BuildsCapstone},
    Capstone, Insn,
};

#[cfg(target_arch = "x86_64")]
use capstone::{
    arch::{self, BuildsCapstone},
    Capstone,
};

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use frida_gum::interceptor::Interceptor;
use frida_gum::{Gum, ModuleMap};
#[cfg(unix)]
use libc::RLIMIT_STACK;
use libc::{c_char, wchar_t};
#[cfg(target_vendor = "apple")]
use libc::{getrlimit, rlimit};
#[cfg(all(unix, not(target_vendor = "apple")))]
use libc::{getrlimit64, rlimit64};
use std::{ffi::c_void, ptr::write_volatile};

use crate::{
    alloc::Allocator,
    asan_errors::{AsanError, AsanErrors, AsanReadWriteError, ASAN_ERRORS},
    FridaOptions,
};

extern "C" {
    fn __register_frame(begin: *mut c_void);
}

/// Get the current thread's TLS address
extern "C" {
    fn tls_ptr() -> *const c_void;
}

#[cfg(target_vendor = "apple")]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANON;
#[cfg(not(target_vendor = "apple"))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANONYMOUS;

// sixteen general purpose registers are put in this order, rax, rbx, rcx, rdx, rbp, rsp, rsi, rdi, r8-r15, plus rip (instrumented location)
#[cfg(target_arch = "x86_64")]
pub const ASAN_SAVE_REGISTER_COUNT: usize = 17;

#[cfg(tareget_arch = "aarch64")]
pub const ASAN_SAVE_REGISTER_COUNT: usize = 32;

/// The frida address sanitizer runtime, providing address sanitization.
/// When executing in `ASAN`, each memory access will get checked, using frida stalker under the hood.
/// The runtime can report memory errors that occurred during execution,
/// even if the target would not have crashed under normal conditions.
/// this helps finding mem errors early.
pub struct AsanRuntime {
    allocator: Allocator,
    regs: [usize; ASAN_SAVE_REGISTER_COUNT],
    blob_report: Option<Box<[u8]>>,
    blob_check_mem_byte: Option<Box<[u8]>>,
    blob_check_mem_halfword: Option<Box<[u8]>>,
    blob_check_mem_dword: Option<Box<[u8]>>,
    blob_check_mem_qword: Option<Box<[u8]>>,
    blob_check_mem_16bytes: Option<Box<[u8]>>,
    blob_check_mem_3bytes: Option<Box<[u8]>>,
    blob_check_mem_6bytes: Option<Box<[u8]>>,
    blob_check_mem_12bytes: Option<Box<[u8]>>,
    blob_check_mem_24bytes: Option<Box<[u8]>>,
    blob_check_mem_32bytes: Option<Box<[u8]>>,
    blob_check_mem_48bytes: Option<Box<[u8]>>,
    blob_check_mem_64bytes: Option<Box<[u8]>>,
    stalked_addresses: HashMap<usize, usize>,
    options: FridaOptions,
    module_map: Option<ModuleMap>,
    shadow_check_func: Option<extern "C" fn(*const c_void, usize) -> bool>,
}

impl AsanRuntime {
    /// Create a new `AsanRuntime`
    #[must_use]
    pub fn new(options: FridaOptions) -> AsanRuntime {
        Self {
            allocator: Allocator::new(options.clone()),
            regs: [0; ASAN_SAVE_REGISTER_COUNT],
            blob_report: None,
            blob_check_mem_byte: None,
            blob_check_mem_halfword: None,
            blob_check_mem_dword: None,
            blob_check_mem_qword: None,
            blob_check_mem_16bytes: None,
            blob_check_mem_3bytes: None,
            blob_check_mem_6bytes: None,
            blob_check_mem_12bytes: None,
            blob_check_mem_24bytes: None,
            blob_check_mem_32bytes: None,
            blob_check_mem_48bytes: None,
            blob_check_mem_64bytes: None,
            stalked_addresses: HashMap::new(),
            options,
            module_map: None,
            shadow_check_func: None,
        }
    }
    /// Initialize the runtime so that it is read for action. Take care not to move the runtime
    /// instance after this function has been called, as the generated blobs would become
    /// invalid!
    pub fn init(&mut self, _gum: &Gum, modules_to_instrument: &[&str]) {
        unsafe {
            ASAN_ERRORS = Some(AsanErrors::new(self.options.clone()));
        }

        #[cfg(target_arch = "aarch64")]
        self.generate_instrumentation_blobs();

        self.generate_shadow_check_function();
        self.unpoison_all_existing_memory();

        self.module_map = Some(ModuleMap::new_from_names(modules_to_instrument));

        #[cfg(target_arch = "aarch64")]
        self.hook_functions(_gum);

        unsafe {
        let mem = self.allocator.alloc(0xac + 2, 8);

        unsafe {mprotect((self.shadow_check_func.unwrap() as usize & 0xffffffffffff000) as *mut c_void, 0x1000, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC)};
        println!("Test0");
        /*
        0x555555916ce9 <libafl_frida::asan_rt::AsanRuntime::init+13033>    je     libafl_frida::asan_rt::AsanRuntime::init+14852 <libafl_frida::asan_rt::AsanRuntime::init+14852>
        0x555555916cef <libafl_frida::asan_rt::AsanRuntime::init+13039>    mov    rdi, r15 <0x555558392338>
        */
        assert!((self.shadow_check_func.unwrap())(((mem as usize) + 0) as *const c_void, 0x00));
        println!("Test1");
        assert!((self.shadow_check_func.unwrap())(((mem as usize) + 0) as *const c_void, 0xac));
        println!("Test2");
        assert!((self.shadow_check_func.unwrap())(((mem as usize) + 2) as *const c_void, 0xac));
        println!("Test3");
        assert!(!(self.shadow_check_func.unwrap())(((mem as usize) + 3) as *const c_void, 0xac));
        println!("Test4");
        assert!(!(self.shadow_check_func.unwrap())(((mem as isize) + -1) as *const c_void, 0xac));
        println!("Test5");
        assert!((self.shadow_check_func.unwrap())(((mem as usize) + 2 + 0xa4) as *const c_void, 8));
        println!("Test6");
        assert!((self.shadow_check_func.unwrap())(((mem as usize) + 2 + 0xa6) as *const c_void, 6));
        println!("Test7");
        assert!(!(self.shadow_check_func.unwrap())(((mem as usize) + 2 + 0xa8) as *const c_void, 6));
        println!("Test8");
        assert!(!(self.shadow_check_func.unwrap())(((mem as usize) + 2 + 0xa8) as *const c_void, 0xac));
        println!("Test9");
        assert!((self.shadow_check_func.unwrap())(((mem as usize) + 4 + 0xa8) as *const c_void, 0x1));
        println!("FIN");
        }
    }

    /// Reset all allocations so that they can be reused for new allocation requests.
    #[allow(clippy::unused_self)]
    pub fn reset_allocations(&mut self) {
        self.allocator.reset();
    }

    /// Check if the test leaked any memory and report it if so.
    pub fn check_for_leaks(&mut self) {
        self.allocator.check_for_leaks();
    }

    /// Returns the `AsanErrors` from the recent run
    #[allow(clippy::unused_self)]
    pub fn errors(&mut self) -> &Option<AsanErrors> {
        unsafe { &ASAN_ERRORS }
    }

    /// Make sure the specified memory is unpoisoned
    #[allow(clippy::unused_self)]
    pub fn unpoison(&mut self, address: usize, size: usize) {
        self.allocator
            .map_shadow_for_region(address, address + size, true);
    }

    /// Make sure the specified memory is poisoned
    #[cfg(target_arch = "aarch64")]
    pub fn poison(&mut self, address: usize, size: usize) {
        Allocator::poison(self.allocator.map_to_shadow(address), size);
    }

    /// Add a stalked address to real address mapping.
    #[inline]
    pub fn add_stalked_address(&mut self, stalked: usize, real: usize) {
        self.stalked_addresses.insert(stalked, real);
    }

    /// Resolves the real address from a stalker stalked address if possible, if there is no
    /// real address, the stalked address is returned.
    #[must_use]
    pub fn real_address_for_stalked(&self, stalked: usize) -> usize {
        self.stalked_addresses
            .get(&stalked)
            .map_or(stalked, |addr| *addr)
    }

    /// Unpoison all the memory that is currently mapped with read/write permissions.
    #[allow(clippy::unused_self)]
    fn unpoison_all_existing_memory(&mut self) {
        self.allocator.unpoison_all_existing_memory();
    }

    /// Register the current thread with the runtime, implementing shadow memory for its stack and
    /// tls mappings.
    #[allow(clippy::unused_self)]
    pub fn register_thread(&mut self) {
        let (stack_start, stack_end) = Self::current_stack();
        self.allocator
            .map_shadow_for_region(stack_start, stack_end, true);

        let (tls_start, tls_end) = Self::current_tls();
        self.allocator
            .map_shadow_for_region(tls_start, tls_end, true);
        println!(
            "registering thread with stack {:x}:{:x} and tls {:x}:{:x}",
            stack_start as usize, stack_end as usize, tls_start as usize, tls_end as usize
        );
    }

    /// Get the maximum stack size for the current stack
    #[must_use]
    #[cfg(target_vendor = "apple")]
    fn max_stack_size() -> usize {
        let mut stack_rlimit = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert!(unsafe { getrlimit(RLIMIT_STACK, &mut stack_rlimit as *mut rlimit) } == 0);

        stack_rlimit.rlim_cur as usize
    }

    /// Get the maximum stack size for the current stack
    #[must_use]
    #[cfg(all(unix, not(target_vendor = "apple")))]
    fn max_stack_size() -> usize {
        let mut stack_rlimit = rlimit64 {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert!(unsafe { getrlimit64(RLIMIT_STACK, &mut stack_rlimit as *mut rlimit64) } == 0);

        stack_rlimit.rlim_cur as usize
    }

    /// Determine the stack start, end for the currently running thread
    ///
    /// # Panics
    /// Panics, if no mapping for the `stack_address` at `0xeadbeef` could be found.
    #[must_use]
    pub fn current_stack() -> (usize, usize) {
        let mut stack_var = 0xeadbeef;
        let stack_address = &mut stack_var as *mut _ as *mut c_void as usize;
        let range_details = RangeDetails::with_address(stack_address as u64).unwrap();
        // Write something to (hopefully) make sure the val isn't optimized out
        unsafe {
            write_volatile(&mut stack_var, 0xfadbeef);
        }

        let start = range_details.memory_range().base_address().0 as usize;
        let end = start + range_details.memory_range().size();

        let max_start = end - Self::max_stack_size();

        let flags = ANONYMOUS_FLAG | MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE;
        #[cfg(not(target_vendor = "apple"))]
        let flags = flags | MapFlags::MAP_STACK;

        if start != max_start {
            let mapping = unsafe {
                mmap(
                    max_start as *mut c_void,
                    start - max_start,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    flags,
                    -1,
                    0,
                )
            };
            assert!(mapping.unwrap() as usize == max_start);
        }
        (max_start, end)
    }

    /// Determine the tls start, end for the currently running thread
    #[must_use]
    fn current_tls() -> (usize, usize) {
        let tls_address = unsafe { tls_ptr() } as usize;

        #[cfg(target_os = "android")]
        // Strip off the top byte, as scudo allocates buffers with top-byte set to 0xb4
        let tls_address = tls_address & 0xffffffffffffff;

        let range_details = RangeDetails::with_address(tls_address as u64).unwrap();
        let start = range_details.memory_range().base_address().0 as usize;
        let end = start + range_details.memory_range().size();
        (start, end)
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn hook_malloc(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(non_snake_case)]
    #[inline]
    fn hook__Znam(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnamRKSt9nothrow_t(&mut self, size: usize, _nothrow: *const c_void) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnamSt11align_val_t(&mut self, size: usize, alignment: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnamSt11align_val_tRKSt9nothrow_t(
        &mut self,
        size: usize,
        alignment: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(non_snake_case)]
    #[inline]
    fn hook__Znwm(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnwmRKSt9nothrow_t(&mut self, size: usize, _nothrow: *const c_void) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnwmSt11align_val_t(&mut self, size: usize, alignment: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnwmSt11align_val_tRKSt9nothrow_t(
        &mut self,
        size: usize,
        alignment: usize,
        _nothrow: *const c_void,
    ) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn hook_calloc(&mut self, nmemb: usize, size: usize) -> *mut c_void {
        let ret = unsafe { self.allocator.alloc(size * nmemb, 8) };
        unsafe {
            memset(ret, 0, size * nmemb);
        }
        ret
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn hook_realloc(&mut self, ptr: *mut c_void, size: usize) -> *mut c_void {
        unsafe {
            let ret = self.allocator.alloc(size, 0x8);
            if ptr != std::ptr::null_mut() && ret != std::ptr::null_mut() {
                let old_size = self.allocator.get_usable_size(ptr);
                let copy_size = if size < old_size { size } else { old_size };
                (ptr as *mut u8).copy_to(ret as *mut u8, copy_size);
            }
            self.allocator.release(ptr);
            ret
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn hook_check_free(&mut self, ptr: *mut c_void) -> bool {
        self.allocator.is_managed(ptr)
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn hook_free(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
    #[inline]
    fn hook_memalign(&mut self, alignment: usize, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn hook_posix_memalign(
        &mut self,
        pptr: *mut *mut c_void,
        alignment: usize,
        size: usize,
    ) -> i32 {
        unsafe {
            *pptr = self.allocator.alloc(size, alignment);
        }
        0
    }

    #[inline]
    #[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
    fn hook_malloc_usable_size(&mut self, ptr: *mut c_void) -> usize {
        self.allocator.get_usable_size(ptr)
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdaPv(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdaPvm(&mut self, ptr: *mut c_void, _ulong: u64) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdaPvmSt11align_val_t(&mut self, ptr: *mut c_void, _ulong: u64, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdaPvRKSt9nothrow_t(&mut self, ptr: *mut c_void, _nothrow: *const c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdaPvSt11align_val_tRKSt9nothrow_t(
        &mut self,
        ptr: *mut c_void,
        _alignment: usize,
        _nothrow: *const c_void,
    ) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdaPvSt11align_val_t(&mut self, ptr: *mut c_void, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdlPv(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdlPvm(&mut self, ptr: *mut c_void, _ulong: u64) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdlPvmSt11align_val_t(&mut self, ptr: *mut c_void, _ulong: u64, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdlPvRKSt9nothrow_t(&mut self, ptr: *mut c_void, _nothrow: *const c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdlPvSt11align_val_tRKSt9nothrow_t(
        &mut self,
        ptr: *mut c_void,
        _alignment: usize,
        _nothrow: *const c_void,
    ) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook__ZdlPvSt11align_val_t(&mut self, ptr: *mut c_void, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_mmap(
        &mut self,
        addr: *const c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> *mut c_void {
        extern "C" {
            fn mmap(
                addr: *const c_void,
                length: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: usize,
            ) -> *mut c_void;
        }
        let res = unsafe { mmap(addr, length, prot, flags, fd, offset) };
        if res != (-1_isize as *mut c_void) {
            self.allocator
                .map_shadow_for_region(res as usize, res as usize + length, true);
        }
        res
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_munmap(&mut self, addr: *const c_void, length: usize) -> i32 {
        extern "C" {
            fn munmap(addr: *const c_void, length: usize) -> i32;
        }
        let res = unsafe { munmap(addr, length) };
        if res != -1 {
            Allocator::poison(self.allocator.map_to_shadow(addr as usize), length);
        }
        res
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_write(&mut self, fd: i32, buf: *const c_void, count: usize) -> usize {
        extern "C" {
            fn write(fd: i32, buf: *const c_void, count: usize) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(buf, count) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "write".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                buf as usize,
                count,
                Backtrace::new(),
            )));
        }
        unsafe { write(fd, buf, count) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_read(&mut self, fd: i32, buf: *mut c_void, count: usize) -> usize {
        extern "C" {
            fn read(fd: i32, buf: *mut c_void, count: usize) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(buf, count) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "read".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                buf as usize,
                count,
                Backtrace::new(),
            )));
        }
        unsafe { read(fd, buf, count) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_fgets(&mut self, s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void {
        extern "C" {
            fn fgets(s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, size as usize) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "fgets".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                size as usize,
                Backtrace::new(),
            )));
        }
        unsafe { fgets(s, size, stream) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_memcmp(&mut self, s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        extern "C" {
            fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memcmp(s1, s2, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_memcpy(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memcpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memcpy(dest, src, n) }
    }

    #[inline]
    #[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
    fn hook_mempcpy(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "mempcpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "mempcpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { mempcpy(dest, src, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_memmove(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memmove".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memmove".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memmove(dest, src, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_memset(&mut self, dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memset".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memset(dest, c, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_memchr(&mut self, s: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memchr(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memchr".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memchr(s, c, n) }
    }

    #[inline]
    #[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
    fn hook_memrchr(&mut self, s: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memrchr(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memrchr".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memrchr(s, c, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_memmem(
        &mut self,
        haystack: *const c_void,
        haystacklen: usize,
        needle: *const c_void,
        needlelen: usize,
    ) -> *mut c_void {
        extern "C" {
            fn memmem(
                haystack: *const c_void,
                haystacklen: usize,
                needle: *const c_void,
                needlelen: usize,
            ) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(haystack, haystacklen) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                haystack as usize,
                haystacklen,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle, needlelen) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                needle as usize,
                needlelen,
                Backtrace::new(),
            )));
        }
        unsafe { memmem(haystack, haystacklen, needle, needlelen) }
    }

    #[cfg(all(not(target_os = "android"), target_arch = "aarch64"))]
    #[inline]
    fn hook_bzero(&mut self, s: *mut c_void, n: usize) {
        extern "C" {
            fn bzero(s: *mut c_void, n: usize);
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "bzero".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { bzero(s, n) }
    }

    #[cfg(all(
        not(target_os = "android"),
        target_arch = "aarch64",
        not(target_vendor = "apple")
    ))]
    #[inline]
    fn hook_explicit_bzero(&mut self, s: *mut c_void, n: usize) {
        extern "C" {
            fn explicit_bzero(s: *mut c_void, n: usize);
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "explicit_bzero".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { explicit_bzero(s, n) }
    }

    #[cfg(all(not(target_os = "android"), target_arch = "aarch64"))]
    #[inline]
    fn hook_bcmp(&mut self, s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        extern "C" {
            fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { bcmp(s1, s2, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strchr(&mut self, s: *mut c_char, c: i32) -> *mut c_char {
        extern "C" {
            fn strchr(s: *mut c_char, c: i32) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strchr".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { strchr(s, c) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strrchr(&mut self, s: *mut c_char, c: i32) -> *mut c_char {
        extern "C" {
            fn strrchr(s: *mut c_char, c: i32) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strrchr".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { strrchr(s, c) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strcasecmp(&mut self, s1: *const c_char, s2: *const c_char) -> i32 {
        extern "C" {
            fn strcasecmp(s1: *const c_char, s2: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcasecmp(s1, s2) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strncasecmp(&mut self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        extern "C" {
            fn strncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncasecmp(s1, s2, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strcat(&mut self, s1: *mut c_char, s2: *const c_char) -> *mut c_char {
        extern "C" {
            fn strcat(s1: *mut c_char, s2: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcat(s1, s2) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strcmp(&mut self, s1: *const c_char, s2: *const c_char) -> i32 {
        extern "C" {
            fn strcmp(s1: *const c_char, s2: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcmp(s1, s2) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strncmp(&mut self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        extern "C" {
            fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncmp(s1, s2, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strcpy(&mut self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        extern "C" {
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "strcpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        unsafe { strcpy(dest, src) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strncpy(&mut self, dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
        extern "C" {
            fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "strncpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncpy(dest, src, n) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_stpcpy(&mut self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        extern "C" {
            fn stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "stpcpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "stpcpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        unsafe { stpcpy(dest, src) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strdup(&mut self, s: *const c_char) -> *mut c_char {
        extern "C" {
            fn strlen(s: *const c_char) -> usize;
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
        }
        let size = unsafe { strlen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strdup".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }

        unsafe {
            let ret = self.allocator.alloc(size, 8) as *mut c_char;
            strcpy(ret, s);
            ret
        }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strlen(&mut self, s: *const c_char) -> usize {
        extern "C" {
            fn strlen(s: *const c_char) -> usize;
        }
        let size = unsafe { strlen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strlen".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                size,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strnlen(&mut self, s: *const c_char, n: usize) -> usize {
        extern "C" {
            fn strnlen(s: *const c_char, n: usize) -> usize;
        }
        let size = unsafe { strnlen(s, n) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strnlen".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                size,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strstr(&mut self, haystack: *const c_char, needle: *const c_char) -> *mut c_char {
        extern "C" {
            fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(haystack as *const c_void, unsafe {
            strlen(haystack)
        }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle as *const c_void, unsafe { strlen(needle) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )));
        }
        unsafe { strstr(haystack, needle) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_strcasestr(&mut self, haystack: *const c_char, needle: *const c_char) -> *mut c_char {
        extern "C" {
            fn strcasestr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(haystack as *const c_void, unsafe {
            strlen(haystack)
        }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle as *const c_void, unsafe { strlen(needle) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )));
        }
        unsafe { strcasestr(haystack, needle) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_atoi(&mut self, s: *const c_char) -> i32 {
        extern "C" {
            fn atoi(s: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atoi".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atoi(s) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_atol(&mut self, s: *const c_char) -> i32 {
        extern "C" {
            fn atol(s: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atol".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atol(s) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_atoll(&mut self, s: *const c_char) -> i64 {
        extern "C" {
            fn atoll(s: *const c_char) -> i64;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atoll".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atoll(s) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_wcslen(&mut self, s: *const wchar_t) -> usize {
        extern "C" {
            fn wcslen(s: *const wchar_t) -> usize;
        }
        let size = unsafe { wcslen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, (size + 1) * 2) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcslen".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s as usize,
                (size + 1) * 2,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_wcscpy(&mut self, dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t {
        extern "C" {
            fn wcscpy(dest: *mut wchar_t, src: *const wchar_t) -> *mut wchar_t;
            fn wcslen(s: *const wchar_t) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, unsafe {
            (wcslen(src) + 1) * 2
        }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "wcscpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                dest as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, unsafe {
            (wcslen(src) + 1) * 2
        }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcscpy".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                src as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        unsafe { wcscpy(dest, src) }
    }

    #[inline]
    #[cfg(target_arch = "aarch64")]
    fn hook_wcscmp(&mut self, s1: *const wchar_t, s2: *const wchar_t) -> i32 {
        extern "C" {
            fn wcscmp(s1: *const wchar_t, s2: *const wchar_t) -> i32;
            fn wcslen(s: *const wchar_t) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { (wcslen(s1) + 1) * 2 })
        {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s1 as usize,
                (unsafe { wcslen(s1) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { (wcslen(s2) + 1) * 2 })
        {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(
                    Interceptor::current_invocation().cpu_context().pc() as usize
                ),
                s2 as usize,
                (unsafe { wcslen(s2) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        unsafe { wcscmp(s1, s2) }
    }

    /// Hook all functions required for ASAN to function, replacing them with our own
    /// implementations.
    #[allow(clippy::items_after_statements)]
    #[cfg(target_arch = "aarch64")]
    fn hook_functions(&mut self, gum: &Gum) {
        let mut interceptor = frida_gum::interceptor::Interceptor::obtain(gum);

        macro_rules! hook_func {
            ($lib:expr, $name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    extern "C" {
                        fn $name($($param: $param_type),*) -> $return_type;
                    }
                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut AsanRuntime);
                        if this.module_map.as_ref().unwrap().find(this.real_address_for_stalked(invocation.return_addr() as usize) as u64).is_some() {
                            this.[<hook_ $name>]($($param),*)
                        } else {
                            $name($($param),*)
                        }
                    }
                    interceptor.replace(
                        frida_gum::Module::find_export_by_name($lib, stringify!($name)).expect("Failed to find function"),
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(self as *mut _ as *mut c_void)
                    ).ok();
                }
            }
        }

        macro_rules! hook_func_with_check {
            ($lib:expr, $name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    extern "C" {
                        fn $name($($param: $param_type),*) -> $return_type;
                    }
                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut AsanRuntime);
                        if this.[<hook_check_ $name>]($($param),*) {
                            this.[<hook_ $name>]($($param),*)
                        } else {
                            $name($($param),*)
                        }
                    }
                    interceptor.replace(
                        frida_gum::Module::find_export_by_name($lib, stringify!($name)).expect("Failed to find function"),
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(self as *mut _ as *mut c_void)
                    ).ok();
                }
            }
        }

        // Hook the memory allocator functions
        hook_func!(None, malloc, (size: usize), *mut c_void);
        hook_func!(None, calloc, (nmemb: usize, size: usize), *mut c_void);
        hook_func!(None, realloc, (ptr: *mut c_void, size: usize), *mut c_void);
        hook_func_with_check!(None, free, (ptr: *mut c_void), ());
        #[cfg(not(target_vendor = "apple"))]
        hook_func!(None, memalign, (size: usize, alignment: usize), *mut c_void);
        hook_func!(
            None,
            posix_memalign,
            (pptr: *mut *mut c_void, size: usize, alignment: usize),
            i32
        );
        #[cfg(not(target_vendor = "apple"))]
        hook_func!(None, malloc_usable_size, (ptr: *mut c_void), usize);
        hook_func!(None, _Znam, (size: usize), *mut c_void);
        hook_func!(
            None,
            _ZnamRKSt9nothrow_t,
            (size: usize, _nothrow: *const c_void),
            *mut c_void
        );
        hook_func!(
            None,
            _ZnamSt11align_val_t,
            (size: usize, alignment: usize),
            *mut c_void
        );
        hook_func!(
            None,
            _ZnamSt11align_val_tRKSt9nothrow_t,
            (size: usize, alignment: usize, _nothrow: *const c_void),
            *mut c_void
        );
        hook_func!(None, _Znwm, (size: usize), *mut c_void);
        hook_func!(
            None,
            _ZnwmRKSt9nothrow_t,
            (size: usize, _nothrow: *const c_void),
            *mut c_void
        );
        hook_func!(
            None,
            _ZnwmSt11align_val_t,
            (size: usize, alignment: usize),
            *mut c_void
        );
        hook_func!(
            None,
            _ZnwmSt11align_val_tRKSt9nothrow_t,
            (size: usize, alignment: usize, _nothrow: *const c_void),
            *mut c_void
        );
        hook_func!(None, _ZdaPv, (ptr: *mut c_void), ());
        hook_func!(None, _ZdaPvm, (ptr: *mut c_void, _ulong: u64), ());
        hook_func!(
            None,
            _ZdaPvmSt11align_val_t,
            (ptr: *mut c_void, _ulong: u64, _alignment: usize),
            ()
        );
        hook_func!(
            None,
            _ZdaPvRKSt9nothrow_t,
            (ptr: *mut c_void, _nothrow: *const c_void),
            ()
        );
        hook_func!(
            None,
            _ZdaPvSt11align_val_t,
            (ptr: *mut c_void, _alignment: usize),
            ()
        );
        hook_func!(
            None,
            _ZdaPvSt11align_val_tRKSt9nothrow_t,
            (ptr: *mut c_void, _alignment: usize, _nothrow: *const c_void),
            ()
        );
        hook_func!(None, _ZdlPv, (ptr: *mut c_void), ());
        hook_func!(None, _ZdlPvm, (ptr: *mut c_void, _ulong: u64), ());
        hook_func!(
            None,
            _ZdlPvmSt11align_val_t,
            (ptr: *mut c_void, _ulong: u64, _alignment: usize),
            ()
        );
        hook_func!(
            None,
            _ZdlPvRKSt9nothrow_t,
            (ptr: *mut c_void, _nothrow: *const c_void),
            ()
        );
        hook_func!(
            None,
            _ZdlPvSt11align_val_t,
            (ptr: *mut c_void, _alignment: usize),
            ()
        );
        hook_func!(
            None,
            _ZdlPvSt11align_val_tRKSt9nothrow_t,
            (ptr: *mut c_void, _alignment: usize, _nothrow: *const c_void),
            ()
        );

        hook_func!(
            None,
            mmap,
            (
                addr: *const c_void,
                length: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: usize
            ),
            *mut c_void
        );
        hook_func!(None, munmap, (addr: *const c_void, length: usize), i32);

        // Hook libc functions which may access allocated memory
        hook_func!(
            None,
            write,
            (fd: i32, buf: *const c_void, count: usize),
            usize
        );
        hook_func!(None, read, (fd: i32, buf: *mut c_void, count: usize), usize);
        hook_func!(
            None,
            fgets,
            (s: *mut c_void, size: u32, stream: *mut c_void),
            *mut c_void
        );
        hook_func!(
            None,
            memcmp,
            (s1: *const c_void, s2: *const c_void, n: usize),
            i32
        );
        hook_func!(
            None,
            memcpy,
            (dest: *mut c_void, src: *const c_void, n: usize),
            *mut c_void
        );
        #[cfg(not(target_vendor = "apple"))]
        hook_func!(
            None,
            mempcpy,
            (dest: *mut c_void, src: *const c_void, n: usize),
            *mut c_void
        );
        hook_func!(
            None,
            memmove,
            (dest: *mut c_void, src: *const c_void, n: usize),
            *mut c_void
        );
        hook_func!(
            None,
            memset,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        hook_func!(
            None,
            memchr,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        #[cfg(not(target_vendor = "apple"))]
        hook_func!(
            None,
            memrchr,
            (s: *mut c_void, c: i32, n: usize),
            *mut c_void
        );
        hook_func!(
            None,
            memmem,
            (
                haystack: *const c_void,
                haystacklen: usize,
                needle: *const c_void,
                needlelen: usize
            ),
            *mut c_void
        );
        #[cfg(not(target_os = "android"))]
        hook_func!(None, bzero, (s: *mut c_void, n: usize), ());
        #[cfg(not(any(target_os = "android", target_vendor = "apple")))]
        hook_func!(None, explicit_bzero, (s: *mut c_void, n: usize), ());
        #[cfg(not(target_os = "android"))]
        hook_func!(
            None,
            bcmp,
            (s1: *const c_void, s2: *const c_void, n: usize),
            i32
        );
        hook_func!(None, strchr, (s: *mut c_char, c: i32), *mut c_char);
        hook_func!(None, strrchr, (s: *mut c_char, c: i32), *mut c_char);
        hook_func!(
            None,
            strcasecmp,
            (s1: *const c_char, s2: *const c_char),
            i32
        );
        hook_func!(
            None,
            strncasecmp,
            (s1: *const c_char, s2: *const c_char, n: usize),
            i32
        );
        hook_func!(
            None,
            strcat,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        hook_func!(None, strcmp, (s1: *const c_char, s2: *const c_char), i32);
        hook_func!(
            None,
            strncmp,
            (s1: *const c_char, s2: *const c_char, n: usize),
            i32
        );
        hook_func!(
            None,
            strcpy,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        hook_func!(
            None,
            strncpy,
            (dest: *mut c_char, src: *const c_char, n: usize),
            *mut c_char
        );
        hook_func!(
            None,
            stpcpy,
            (dest: *mut c_char, src: *const c_char),
            *mut c_char
        );
        hook_func!(None, strdup, (s: *const c_char), *mut c_char);
        hook_func!(None, strlen, (s: *const c_char), usize);
        hook_func!(None, strnlen, (s: *const c_char, n: usize), usize);
        hook_func!(
            None,
            strstr,
            (haystack: *const c_char, needle: *const c_char),
            *mut c_char
        );
        hook_func!(
            None,
            strcasestr,
            (haystack: *const c_char, needle: *const c_char),
            *mut c_char
        );
        hook_func!(None, atoi, (nptr: *const c_char), i32);
        hook_func!(None, atol, (nptr: *const c_char), i32);
        hook_func!(None, atoll, (nptr: *const c_char), i64);
        hook_func!(None, wcslen, (s: *const wchar_t), usize);
        hook_func!(
            None,
            wcscpy,
            (dest: *mut wchar_t, src: *const wchar_t),
            *mut wchar_t
        );
        hook_func!(None, wcscmp, (s1: *const wchar_t, s2: *const wchar_t), i32);
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::too_many_lines)]
    extern "C" fn handle_trap(&mut self) {
        let mut actual_pc = self.regs[16];
        actual_pc = match self.stalked_addresses.get(&actual_pc) {
            Some(addr) => *addr,
            None => actual_pc,
        };

        let backtrace = Backtrace::new();

        // Just a place holder... for now
        let error = AsanError::Unknown((self.regs, actual_pc, (0, 0, 0, 0), backtrace));

        println!("{:#?}", self.regs);

        AsanErrors::get_mut().report_error(error)
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::cast_sign_loss)] // for displacement
    #[allow(clippy::too_many_lines)]
    extern "C" fn handle_trap(&mut self) {
        let mut actual_pc = self.regs[31];
        actual_pc = match self.stalked_addresses.get(&actual_pc) {
            Some(addr) => *addr,
            None => actual_pc,
        };

        let cs = Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .unwrap();

        let instructions = cs
            .disasm_count(
                unsafe { std::slice::from_raw_parts(actual_pc as *mut u8, 24) },
                actual_pc as u64,
                3,
            )
            .unwrap();
        let instructions = instructions.iter().collect::<Vec<Insn>>();
        let mut insn = instructions.first().unwrap();
        if insn.mnemonic().unwrap() == "msr" && insn.op_str().unwrap() == "nzcv, x0" {
            insn = instructions.get(2).unwrap();
            actual_pc = insn.address() as usize;
        }

        let detail = cs.insn_detail(insn).unwrap();
        let arch_detail = detail.arch_detail();
        let (mut base_reg, mut index_reg, displacement) =
            if let Arm64Operand(arm64operand) = arch_detail.operands().last().unwrap() {
                if let Arm64OperandType::Mem(opmem) = arm64operand.op_type {
                    (opmem.base().0, opmem.index().0, opmem.disp())
                } else {
                    (0, 0, 0)
                }
            } else {
                (0, 0, 0)
            };

        if capstone::arch::arm64::Arm64Reg::ARM64_REG_X0 as u16 <= base_reg
            && base_reg <= capstone::arch::arm64::Arm64Reg::ARM64_REG_X28 as u16
        {
            base_reg -= capstone::arch::arm64::Arm64Reg::ARM64_REG_X0 as u16;
        } else if base_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_X29 as u16 {
            base_reg = 29u16;
        } else if base_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_X30 as u16 {
            base_reg = 30u16;
        } else if base_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_SP as u16
            || base_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_WSP as u16
            || base_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_XZR as u16
            || base_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_WZR as u16
        {
            base_reg = 31u16;
        } else if capstone::arch::arm64::Arm64Reg::ARM64_REG_W0 as u16 <= base_reg
            && base_reg <= capstone::arch::arm64::Arm64Reg::ARM64_REG_W30 as u16
        {
            base_reg -= capstone::arch::arm64::Arm64Reg::ARM64_REG_W0 as u16;
        } else if capstone::arch::arm64::Arm64Reg::ARM64_REG_S0 as u16 <= base_reg
            && base_reg <= capstone::arch::arm64::Arm64Reg::ARM64_REG_S31 as u16
        {
            base_reg -= capstone::arch::arm64::Arm64Reg::ARM64_REG_S0 as u16;
        }

        #[allow(clippy::cast_possible_wrap)]
        let mut fault_address =
            (self.regs[base_reg as usize] as isize + displacement as isize) as usize;

        if index_reg == 0 {
            index_reg = 0xffff;
        } else {
            if capstone::arch::arm64::Arm64Reg::ARM64_REG_X0 as u16 <= index_reg
                && index_reg <= capstone::arch::arm64::Arm64Reg::ARM64_REG_X28 as u16
            {
                index_reg -= capstone::arch::arm64::Arm64Reg::ARM64_REG_X0 as u16;
            } else if index_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_X29 as u16 {
                index_reg = 29u16;
            } else if index_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_X30 as u16 {
                index_reg = 30u16;
            } else if index_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_SP as u16
                || index_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_WSP as u16
                || index_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_XZR as u16
                || index_reg == capstone::arch::arm64::Arm64Reg::ARM64_REG_WZR as u16
            {
                index_reg = 31u16;
            } else if capstone::arch::arm64::Arm64Reg::ARM64_REG_W0 as u16 <= index_reg
                && index_reg <= capstone::arch::arm64::Arm64Reg::ARM64_REG_W30 as u16
            {
                index_reg -= capstone::arch::arm64::Arm64Reg::ARM64_REG_W0 as u16;
            } else if capstone::arch::arm64::Arm64Reg::ARM64_REG_S0 as u16 <= index_reg
                && index_reg <= capstone::arch::arm64::Arm64Reg::ARM64_REG_S31 as u16
            {
                index_reg -= capstone::arch::arm64::Arm64Reg::ARM64_REG_S0 as u16;
            }
            fault_address += self.regs[index_reg as usize] as usize;
        }

        let backtrace = Backtrace::new();

        let (stack_start, stack_end) = Self::current_stack();
        #[allow(clippy::option_if_let_else)]
        let error = if fault_address >= stack_start && fault_address < stack_end {
            if insn.mnemonic().unwrap().starts_with('l') {
                AsanError::StackOobRead((
                    self.regs,
                    actual_pc,
                    (base_reg, index_reg, displacement as usize, fault_address),
                    backtrace,
                ))
            } else {
                AsanError::StackOobWrite((
                    self.regs,
                    actual_pc,
                    (base_reg, index_reg, displacement as usize, fault_address),
                    backtrace,
                ))
            }
        } else if let Some(metadata) = self
            .allocator
            .find_metadata(fault_address, self.regs[base_reg as usize])
        {
            let asan_readwrite_error = AsanReadWriteError {
                registers: self.regs,
                pc: actual_pc,
                fault: (base_reg, index_reg, displacement as usize, fault_address),
                metadata: metadata.clone(),
                backtrace,
            };
            if insn.mnemonic().unwrap().starts_with('l') {
                if metadata.freed {
                    AsanError::ReadAfterFree(asan_readwrite_error)
                } else {
                    AsanError::OobRead(asan_readwrite_error)
                }
            } else if metadata.freed {
                AsanError::WriteAfterFree(asan_readwrite_error)
            } else {
                AsanError::OobWrite(asan_readwrite_error)
            }
        } else {
            AsanError::Unknown((
                self.regs,
                actual_pc,
                (base_reg, index_reg, displacement as usize, fault_address),
                backtrace,
            ))
        };
        AsanErrors::get_mut().report_error(error);
    }

    /*
    #include <stdio.h>
    #include <stdint.h>
    uint8_t shadow_bit = 44;

    uint64_t generate_shadow_check_function(uint64_t start, uint64_t size){
        // calculate the shadow address
        uint64_t addr = 1;
        addr = addr << shadow_bit;
        addr = addr + (start >> 3);
        uint64_t mask = (1ULL << (shadow_bit + 1)) - 1;
        addr = addr & mask;

        if(size == 0){
            // goto return_success
            return 1;
        }
        else{
            // check if the ptr is not aligned to 8 bytes
            uint8_t remainder = start & 0b111;
            if(remainder != 0){
                // we need to test the high bits from the first shadow byte
                uint8_t shift;
                if(size < 8){
                    shift = size;
                }
                else{
                    shift = 8 - remainder;
                }
                // goto check_bits
                uint8_t mask = (1 << shift) - 1;

                // bitwise reverse for amd64 :<
                // https://stackoverflow.com/questions/2602823/in-c-c-whats-the-simplest-way-to-reverse-the-order-of-bits-in-a-byte
                uint8_t val = *(uint8_t *)addr;
                val = (val & 0xf0) >> 4 | (val & 0x0f) << 4;
                val = (val & 0xff) >> 2 | (val & 0x33) << 2;
                val = (val & 0xaa) >> 1 | (val & 0x55) << 1;
                val = (val >> remainder);
                if((val & mask) != mask){
                    // goto return failure
                    return 0;
                }

                size = size - shift;
                addr += 1;
            }

            // no_start_offset
            uint64_t num_shadow_bytes = size >> 3;
            uint64_t mask = -1;

            while(true){
                if(num_shadow_bytes < 8){
                    // goto less_than_8_shadow_bytes_remaining
                    break;
                }
                else{
                    uint64_t val = *(uint64_t *)addr;
                    addr += 8;
                    if(val != mask){
                        // goto return failure
                        return 0;
                    }
                    num_shadow_bytes -= 8;
                    size -= 64;
                }
            }

            while(true){
                if(num_shadow_bytes < 1){
                    // goto check_trailing_bits
                    break;
                }
                else{
                    uint8_t val = *(uint8_t *)addr;
                    addr += 1;
                    if(val != 0xff){
                        // goto return failure
                        return 0;
                    }
                    num_shadow_bytes -= 1;
                    size -= 8;
                }
            }

            if(size == 0){
                // goto return success
                return 1;
            }

            uint8_t mask2 = ((1 << (size & 0b111)) - 1);
            uint8_t val = *(uint8_t *)addr;
            val = (val & 0xf0) >> 4 | (val & 0x0f) << 4;
            val = (val & 0xff) >> 2 | (val & 0x33) << 2;
            val = (val & 0xaa) >> 1 | (val & 0x55) << 1;

            if((val & mask2) != mask2){
                // goto return failure
                return 0;
            }
            return 1;
        }
    }
        */
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::unused_self, clippy::identity_op)]
    fn generate_shadow_check_function(&mut self) {
        let shadow_bit = self.allocator.shadow_bit();
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);

        // Rdi start, Rsi size
        dynasm!(ops
        ;    .arch x64
        ;    mov     cl, BYTE shadow_bit as i8
        ;    mov     eax, 1
        ;    mov     edx, 1
        ;    shl     rdx, cl
        ;    mov     r9d, 2
        ;    shl     r9, cl
        ;    test    rsi, rsi
        ;    je      >LBB0_15
        ;    mov     rcx, rdi
        ;    shr     rcx, 3
        ;    add     rdx, rcx
        ;    add     r9, -1
        ;    and     r9, rdx
        ;    and     edi, 7
        ;    je      >LBB0_4
        ;    mov     cl, 8
        ;    sub     cl, dil
        ;    cmp     rsi, 8
        ;    movzx   ecx, cl
        ;    mov     r8d, esi
        ;    cmovae  r8d, ecx
        ;    mov     r10d, -1
        ;    mov     ecx, r8d
        ;    shl     r10d, cl
        ;    mov     cl, BYTE [r9]
        ;    rol     cl, 4
        ;    mov     edx, ecx
        ;    shr     dl, 2
        ;    shl     cl, 2
        ;    and     cl, -52
        ;    or      cl, dl
        ;    mov     edx, ecx
        ;    shr     dl, 1
        ;    and     dl, 85
        ;    add     cl, cl
        ;    and     cl, -86
        ;    or      cl, dl
        ;    movzx   edx, cl
        ;    mov     ecx, edi
        ;    shr     edx, cl
        ;    not     r10d
        ;    movzx   ecx, r10b
        ;    and     edx, ecx
        ;    cmp     edx, ecx
        ;    jne     >LBB0_11
        ;    movzx   ecx, r8b
        ;    sub     rsi, rcx
        ;    add     r9, 1
        ;LBB0_4:
        ;    mov     r8, rsi
        ;    shr     r8, 3
        ;    mov     r10, r8
        ;    and     r10, -8
        ;    mov     edi, r8d
        ;    and     edi, 7
        ;    add     r10, r9
        ;    and     esi, 63
        ;    mov     rdx, r8
        ;    mov     rcx, r9
        ;LBB0_5:
        ;    cmp     rdx, 7
        ;    jbe     >LBB0_8
        ;    add     rdx, -8
        ;    cmp     QWORD [rcx], -1
        ;    lea     rcx, [rcx + 8]
        ;    je      <LBB0_5
        ;    jmp     >LBB0_11
        ;LBB0_8:
        ;    lea     rcx, [8*rdi]
        ;    sub     rsi, rcx
        ;LBB0_9:
        ;    test    rdi, rdi
        ;    je      >LBB0_13
        ;    add     rdi, -1
        ;    cmp     BYTE [r10], -1
        ;    lea     r10, [r10 + 1]
        ;    je      <LBB0_9
        ;LBB0_11:
        ;    xor     eax, eax
        ;    ret
        ;LBB0_13:
        ;    test    rsi, rsi
        ;    je      >LBB0_15
        ;    and     sil, 7
        ;    mov     dl, -1
        ;    mov     ecx, esi
        ;    shl     dl, cl
        ;    not     dl
        ;    mov     cl, BYTE [r8 + r9]
        ;    rol     cl, 4
        ;    mov     eax, ecx
        ;    shr     al, 2
        ;    shl     cl, 2
        ;    and     cl, -52
        ;    or      cl, al
        ;    mov     eax, ecx
        ;    shr     al, 1
        ;    and     al, 85
        ;    add     cl, cl
        ;    and     cl, -86
        ;    or      cl, al
        ;    and     cl, dl
        ;    xor     eax, eax
        ;    cmp     cl, dl
        ;    sete    al
        ;LBB0_15:
        ;    ret
            );

        let blob = ops.finalize().unwrap();
        unsafe {
            let mapping = mmap(
                std::ptr::null_mut(),
                0x1000,
                ProtFlags::all(),
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();
            blob.as_ptr()
                .copy_to_nonoverlapping(mapping as *mut u8, blob.len());
            self.shadow_check_func = Some(std::mem::transmute(mapping as *mut u8));
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::unused_self, clippy::identity_op)] // identity_op appears to be a false positive in ubfx
    fn generate_shadow_check_function(&mut self) {
        let shadow_bit = self.allocator.shadow_bit();
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        dynasm!(ops
            ; .arch x64

            // calculate the shadow address
            ; mov x5, #1
            ; add x5, xzr, x5, lsl #shadow_bit
            ; add x5, x5, x0, lsr #3
            ; ubfx x5, x5, #0, #(shadow_bit + 1)

            ; cmp x1, #0
            ; b.eq >return_success
            // check if the ptr is not aligned to 8 bytes
            ; ands x6, x0, #7
            ; b.eq >no_start_offset

            // we need to test the high bits from the first shadow byte
            ; ldrh w7, [x5, #0]
            ; rev16 w7, w7
            ; rbit w7, w7
            ; lsr x7, x7, #16
            ; lsr x7, x7, x6

            ; cmp x1, #8
            ; b.lt >dont_fill_to_8
            ; mov x2, #8
            ; sub x6, x2, x6
            ; b >check_bits
            ; dont_fill_to_8:
            ; mov x6, x1
            ; check_bits:
            ; mov x2, #1
            ; lsl x2, x2, x6
            ; sub x4, x2, #1

            // if shadow_bits & size_to_test != size_to_test: fail
            ; and x7, x7, x4
            ; cmp x7, x4
            ; b.ne >return_failure

            // size -= size_to_test
            ; sub x1, x1, x6
            // shadow_addr += 1 (we consumed the initial byte in the above test)
            ; add x5, x5, 1

            ; no_start_offset:
            // num_shadow_bytes = size / 8
            ; lsr x4, x1, #3
            ; eor x3, x3, x3
            ; sub x3, x3, #1

            // if num_shadow_bytes < 8; then goto check_bytes; else check_8_shadow_bytes
            ; check_8_shadow_bytes:
            ; cmp x4, #0x8
            ; b.lt >less_than_8_shadow_bytes_remaining
            ; ldr x7, [x5], #8
            ; cmp x7, x3
            ; b.ne >return_failure
            ; sub x4, x4, #8
            ; sub x1, x1, #64
            ; b <check_8_shadow_bytes

            ; less_than_8_shadow_bytes_remaining:
            ; cmp x4, #1
            ; b.lt >check_trailing_bits
            ; ldrb w7, [x5], #1
            ; cmp w7, #0xff
            ; b.ne >return_failure
            ; sub x4, x4, #1
            ; sub x1, x1, #8
            ; b <less_than_8_shadow_bytes_remaining

            ; check_trailing_bits:
            ; cmp x1, #0x0
            ; b.eq >return_success

            ; and x4, x1, #7
            ; mov x2, #1
            ; lsl x2, x2, x4
            ; sub x4, x2, #1

            ; ldrh w7, [x5, #0]
            ; rev16 w7, w7
            ; rbit w7, w7
            ; lsr x7, x7, #16
            ; and x7, x7, x4
            ; cmp x7, x4
            ; b.ne >return_failure

            ; return_success:
            ; mov x0, #1
            ; b >prologue

            ; return_failure:
            ; mov x0, #0


            ; prologue:
            ; ret
        );

        let blob = ops.finalize().unwrap();
        unsafe {
            let mapping = mmap(
                std::ptr::null_mut(),
                0x1000,
                ProtFlags::all(),
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
            .unwrap();
            blob.as_ptr()
                .copy_to_nonoverlapping(mapping as *mut u8, blob.len());
            self.shadow_check_func = Some(std::mem::transmute(mapping as *mut u8));
        }
    }

    /*
    #include <stdio.h>
    #include <stdint.h>
    uint8_t shadow_bit = 8;
    uint8_t bit = 3;
    uint64_t generate_shadow_check_blob(uint64_t start){
        uint64_t addr = 1;
        addr = addr << shadow_bit;
        addr = addr + (start >> 3);
        uint64_t mask = (1ULL << (shadow_bit + 1)) - 1;
        addr = addr & mask;

        uint8_t val = *(uint8_t *)addr;
        uint8_t remainder = start & 0b111;
        val = (val & 0xf0) >> 4 | (val & 0x0f) << 4;
        val = (val & 0xff) >> 2 | (val & 0x33) << 2;
        val = (val & 0xaa) >> 1 | (val & 0x55) << 1;
        val = (val >> remainder);

        uint8_t mask2 = (1 << bit) - 1;
        if((val & mask2) == mask2){
            // success
            return 0;
        }
        else{
            // failure
            return 1;
        }
    }
    */
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::unused_self)]
    fn generate_shadow_check_blob(&mut self, bit: u32) -> Box<[u8]> {
        let shadow_bit = self.allocator.shadow_bit();
        // Rcx, Rax, Rdi, Rdx, Rsi are used, so we save them in emit_shadow_check
        macro_rules! shadow_check{
            ($ops:ident, $bit:expr) => {dynasm!($ops
                ;   .arch x64
                ;   mov     cl, shadow_bit as i8
                ;   mov     eax, 1
                ;   shl     rax, cl
                ;   mov     rdx, rdi
                ;   shr     rdx, 3
                ;   mov     esi, 2
                ;   shl     rsi, cl
                ;   add     rdx, rax
                ;   add     rsi, -1
                ;   and     rsi, rdx
                ;   mov     al, BYTE [rsi]
                ;   and     dil, 7
                ;   rol     al, 4
                ;   mov     ecx, eax
                ;   shr     cl, 2
                ;   shl     al, 2
                ;   and     al, -52
                ;   or      al, cl
                ;   mov     ecx, eax
                ;   shr     cl, 1
                ;   and     cl, 85
                ;   add     al, al
                ;   and     al, -86
                ;   or      al, cl
                ;   mov     ecx, edi
                ;   shr     al, cl
                ;   mov     cl, bit as i8
                ;   mov     edx, -1
                ;   shl     edx, cl
                ;   not     edx
                ;   movzx   ecx, al
                ;   movzx   edx, dl
                ;   and     ecx, edx
                ;   xor     eax, eax
                ;   cmp     ecx, edx
                ;   je      >done
                ;   lea     rsi, [>done] // leap 10 bytes forward
                ;   nop // jmp takes 10 bytes at most so we want to allocate 10 bytes buffer (?)
                ;   nop
                ;   nop
                ;   nop
                ;   nop
                ;   nop
                ;   nop
                ;   nop
                ;   nop
                ;   nop
                ;done:
            );};
        }
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        shadow_check!(ops, bit);
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len() - 10].to_vec().into_boxed_slice() //????
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::unused_self)]
    fn generate_shadow_check_blob(&mut self, bit: u32) -> Box<[u8]> {
        let shadow_bit = self.allocator.shadow_bit();
        macro_rules! shadow_check {
            ($ops:ident, $bit:expr) => {dynasm!($ops
                ; .arch aarch64

                ; mov x1, #1
                ; add x1, xzr, x1, lsl #shadow_bit
                ; add x1, x1, x0, lsr #3
                ; ubfx x1, x1, #0, #(shadow_bit + 1)
                ; ldrh w1, [x1, #0]
                ; and x0, x0, #7
                ; rev16 w1, w1
                ; rbit w1, w1
                ; lsr x1, x1, #16
                ; lsr x1, x1, x0
                ; tbnz x1, #$bit, >done

                ; adr x1, >done
                ; nop // will be replaced by b to report
                ; done:
            );};
        }

        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check!(ops, bit);
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len() - 4].to_vec().into_boxed_slice()
    }

    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::unused_self)]
    fn generate_shadow_check_exact_blob(&mut self, val: u64) -> Box<[u8]> {
        let shadow_bit = self.allocator.shadow_bit();
        macro_rules! shadow_check_exact {
            ($ops:ident, $val:expr) => {dynasm!($ops
                ; .arch aarch64

                ; mov x1, #1
                ; add x1, xzr, x1, lsl #shadow_bit
                ; add x1, x1, x0, lsr #3
                ; ubfx x1, x1, #0, #(shadow_bit + 1)
                ; ldrh w1, [x1, #0]
                ; and x0, x0, #7
                ; rev16 w1, w1
                ; rbit w1, w1
                ; lsr x1, x1, #16
                ; lsr x1, x1, x0
                ; .dword -717536768 // 0xd53b4200 //mrs x0, NZCV
                ; stp x2, x3, [sp, #-0x10]!
                ; mov x2, $val
                ; ands x1, x1, x2
                ; ldp x2, x3, [sp], 0x10
                ; b.ne >done

                ; adr x1, >done
                ; nop // will be replaced by b to report
                ; done:
            );};
        }

        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        shadow_check_exact!(ops, val);
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len() - 4].to_vec().into_boxed_slice()
    }

    // Save registers into self_regs_addr
    // Five registers, Rdi, Rsi, Rdx, Rcx, Rax are saved in emit_shadow_check before entering this function
    // So we retrieve them after saving other registers
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::similar_names)]
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::too_many_lines)]
    fn generate_instrumentation_blobs(&mut self) {
        let mut ops_report = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        dynasm!(ops_report
            ; .arch x64
            ; report:
            ; lea rdi, [>self_regs_addr] // load self.regs into rdi
            ; mov [rdi + 0x80], rsi // return address is loaded into rsi in generate_shadow_check_blob
            ; mov [rdi + 0x8], rbx
            ; mov [rdi + 0x20], rbp
            ; mov [rdi + 0x28], rsp
            ; mov [rdi + 0x40], r8
            ; mov [rdi + 0x48], r9
            ; mov [rdi + 0x50], r10
            ; mov [rdi + 0x58], r11
            ; mov [rdi + 0x60], r12
            ; mov [rdi + 0x68], r13
            ; mov [rdi + 0x70], r14
            ; mov [rdi + 0x78], r15
            ; mov rax, [rsp + 0x8]
            ; mov [rdi + 0x0], rax
            ; mov rcx, [rsp + 0x10]
            ; mov [rdi + 0x10], rcx
            ; mov rdx, [rsp + 0x18]
            ; mov [rdi + 0x18], rdx
            ; mov rsi, [rsp + 0x20]
            ; mov [rdi + 0x30], rsi
            ; mov rsi, rdi // Lastly, we want to save rdi, but we have to copy the address of self.regs into another register
            ; mov rdi, [rsp + 0x28]
            ; mov [rsi + 0x0], rdi
            ; self_addr:
            ; .qword self as *mut _  as *mut c_void as i64
            ; self_regs_addr:
            ; .qword &mut self.regs as *mut _ as *mut c_void as i64
        );
        self.blob_check_mem_byte = Some(self.generate_shadow_check_blob(0));
        self.blob_check_mem_halfword = Some(self.generate_shadow_check_blob(1));
        self.blob_check_mem_dword = Some(self.generate_shadow_check_blob(2));
        self.blob_check_mem_qword = Some(self.generate_shadow_check_blob(3));
        self.blob_check_mem_16bytes = Some(self.generate_shadow_check_blob(4));
    }

    ///
    /// Generate the instrumentation blobs for the current arch.
    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::similar_names)] // We allow things like dword and qword
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::too_many_lines)]
    fn generate_instrumentation_blobs(&mut self) {
        let mut ops_report = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        dynasm!(ops_report
            ; .arch aarch64

            ; report:
            ; stp x29, x30, [sp, #-0x10]!
            ; mov x29, sp
            // save the nvcz and the 'return-address'/address of instrumented instruction
            ; stp x0, x1, [sp, #-0x10]!

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
            ; mov x28, x0

            ; mov x25, x1 // address of instrumented instruction.
            ; str x25, [x28, 0xf8]

            ; .dword 0xd53b4218u32 as i32 // mrs x24, nzcv
            ; ldp x0, x1, [sp, 0x20]
            ; stp x0, x1, [x28]

            ; adr x25, <report
            ; adr x0, >eh_frame_fde
            ; adr x27, >fde_address
            ; ldr w26, [x27]
            ; cmp w26, #0x0
            ; b.ne >skip_register
            ; sub x25, x25, x27
            ; str w25, [x27]
            ; ldr x1, >register_frame_func
            //; brk #11
            ; blr x1
            ; skip_register:
            ; ldr x0, >self_addr
            ; ldr x1, >trap_func
            ; blr x1

            ; .dword 0xd51b4218u32 as i32 // msr nzcv, x24
            ; ldr x0, >self_regs_addr
            ; ldp x2, x3, [x0, #0x10]
            ; ldp x4, x5, [x0, #0x20]
            ; ldp x6, x7, [x0, #0x30]
            ; ldp x8, x9, [x0, #0x40]
            ; ldp x10, x11, [x0, #0x50]
            ; ldp x12, x13, [x0, #0x60]
            ; ldp x14, x15, [x0, #0x70]
            ; ldp x16, x17, [x0, #0x80]
            ; ldp x18, x19, [x0, #0x90]
            ; ldp x20, x21, [x0, #0xa0]
            ; ldp x22, x23, [x0, #0xb0]
            ; ldp x24, x25, [x0, #0xc0]
            ; ldp x26, x27, [x0, #0xd0]
            ; ldp x28, x29, [x0, #0xe0]
            ; ldp x30, xzr, [x0, #0xf0]

            // restore nzcv. and 'return address'
            ; ldp x0, x1, [sp], #0x10
            ; ldp x29, x30, [sp], #0x10
            ; br x1 // go back to the 'return address'

            ; self_addr:
            ; .qword self as *mut _  as *mut c_void as i64
            ; self_regs_addr:
            ; .qword &mut self.regs as *mut _ as *mut c_void as i64
            ; trap_func:
            ; .qword AsanRuntime::handle_trap as *mut c_void as i64
            ; register_frame_func:
            ; .qword __register_frame as *mut c_void as i64
            ; eh_frame_cie:
            ; .dword 0x14
            ; .dword 0x00
            ; .dword 0x00527a01
            ; .dword 0x011e7c01
            ; .dword 0x001f0c1b
            ; eh_frame_fde:
            ; .dword 0x14
            ; .dword 0x18
            ; fde_address:
            ; .dword 0x0 // <-- address offset goes here
            ; .dword 0x104
                //advance_loc 12
                //def_cfa r29 (x29) at offset 16
                //offset r30 (x30) at cfa-8
                //offset r29 (x29) at cfa-16
            ; .dword 0x1d0c4c00
            ; .dword 0x9d029e10u32 as i32
            ; .dword 0x04
            // empty next FDE:
            ; .dword 0x0
            ; .dword 0x0
        );
        self.blob_report = Some(ops_report.finalize().unwrap().into_boxed_slice());

        self.blob_check_mem_byte = Some(self.generate_shadow_check_blob(0));
        self.blob_check_mem_halfword = Some(self.generate_shadow_check_blob(1));
        self.blob_check_mem_dword = Some(self.generate_shadow_check_blob(2));
        self.blob_check_mem_qword = Some(self.generate_shadow_check_blob(3));
        self.blob_check_mem_16bytes = Some(self.generate_shadow_check_blob(4));

        self.blob_check_mem_3bytes = Some(self.generate_shadow_check_exact_blob(3));
        self.blob_check_mem_6bytes = Some(self.generate_shadow_check_exact_blob(6));
        self.blob_check_mem_12bytes = Some(self.generate_shadow_check_exact_blob(12));
        self.blob_check_mem_24bytes = Some(self.generate_shadow_check_exact_blob(24));
        self.blob_check_mem_32bytes = Some(self.generate_shadow_check_exact_blob(32));
        self.blob_check_mem_48bytes = Some(self.generate_shadow_check_exact_blob(48));
        self.blob_check_mem_64bytes = Some(self.generate_shadow_check_exact_blob(64));
    }

    /// Get the blob which implements the report funclet
    #[must_use]
    #[inline]
    pub fn blob_report(&self) -> &[u8] {
        self.blob_report.as_ref().unwrap()
    }

    /// Get the blob which checks a byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_byte(&self) -> &[u8] {
        self.blob_check_mem_byte.as_ref().unwrap()
    }

    /// Get the blob which checks a halfword access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_halfword(&self) -> &[u8] {
        self.blob_check_mem_halfword.as_ref().unwrap()
    }

    /// Get the blob which checks a dword access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_dword(&self) -> &[u8] {
        self.blob_check_mem_dword.as_ref().unwrap()
    }

    /// Get the blob which checks a qword access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_qword(&self) -> &[u8] {
        self.blob_check_mem_qword.as_ref().unwrap()
    }

    /// Get the blob which checks a 16 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_16bytes(&self) -> &[u8] {
        self.blob_check_mem_16bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 3 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_3bytes(&self) -> &[u8] {
        self.blob_check_mem_3bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 6 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_6bytes(&self) -> &[u8] {
        self.blob_check_mem_6bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 12 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_12bytes(&self) -> &[u8] {
        self.blob_check_mem_12bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 24 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_24bytes(&self) -> &[u8] {
        self.blob_check_mem_24bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 32 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_32bytes(&self) -> &[u8] {
        self.blob_check_mem_32bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 48 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_48bytes(&self) -> &[u8] {
        self.blob_check_mem_48bytes.as_ref().unwrap()
    }

    /// Get the blob which checks a 64 byte access
    #[must_use]
    #[inline]
    pub fn blob_check_mem_64bytes(&self) -> &[u8] {
        self.blob_check_mem_64bytes.as_ref().unwrap()
    }
}
