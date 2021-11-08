/*!
The frida address sanitizer runtime provides address sanitization.
When executing in `ASAN`, each memory access will get checked, using frida stalker under the hood.
The runtime can report memory errors that occurred during execution,
even if the target would not have crashed under normal conditions.
this helps finding mem errors early.
*/

use frida_gum::NativePointer;
use frida_gum::RangeDetails;
use hashbrown::HashMap;

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
    arch::{self, x86::X86OperandType, ArchOperand::X86Operand, BuildsCapstone},
    Capstone, RegAccessType, RegId,
};

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use frida_gum::interceptor::Interceptor;
use frida_gum::{Gum, Module, ModuleMap};
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

// sixteen general purpose registers are put in this order, rax, rbx, rcx, rdx, rbp, rsp, rsi, rdi, r8-r15, plus instrumented rip, accessed memory addr and true rip
#[cfg(target_arch = "x86_64")]
pub const ASAN_SAVE_REGISTER_COUNT: usize = 19;

#[cfg(target_arch = "x86_64")]
pub const ASAN_SAVE_REGISTER_NAMES: [&str; ASAN_SAVE_REGISTER_COUNT] = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rbp",
    "rsp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "instrumented rip",
    "fault address",
    "actual rip",
];

#[cfg(target_arch = "aarch64")]
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

        self.generate_instrumentation_blobs();

        self.generate_shadow_check_function();
        self.unpoison_all_existing_memory();

        self.module_map = Some(ModuleMap::new_from_names(modules_to_instrument));

        self.hook_functions(_gum);

        /*

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

        for i in 0..0xad {
            assert!((self.shadow_check_func.unwrap())(((mem as usize) + i) as *const c_void, 0x01));
        }
        // assert!((self.shadow_check_func.unwrap())(((mem2 as usize) + 8875) as *const c_void, 4));
        }

        */
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
    fn pc() -> usize {
        Interceptor::current_invocation().cpu_context().pc() as usize
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn pc() -> usize {
        Interceptor::current_invocation().cpu_context().rip() as usize
    }

    #[inline]
    fn hook_malloc(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__Znam(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnamRKSt9nothrow_t(&mut self, size: usize, _nothrow: *const c_void) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnamSt11align_val_t(&mut self, size: usize, alignment: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

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

    #[allow(non_snake_case)]
    #[inline]
    fn hook__Znwm(&mut self, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnwmRKSt9nothrow_t(&mut self, size: usize, _nothrow: *const c_void) -> *mut c_void {
        unsafe { self.allocator.alloc(size, 8) }
    }

    #[allow(non_snake_case)]
    #[inline]
    fn hook__ZnwmSt11align_val_t(&mut self, size: usize, alignment: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

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

    #[inline]
    fn hook_calloc(&mut self, nmemb: usize, size: usize) -> *mut c_void {
        let ret = unsafe { self.allocator.alloc(size * nmemb, 8) };
        unsafe {
            memset(ret, 0, size * nmemb);
        }
        ret
    }

    #[inline]
    #[allow(clippy::cmp_null)]
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

    #[inline]
    fn hook_check_free(&mut self, ptr: *mut c_void) -> bool {
        self.allocator.is_managed(ptr)
    }

    #[inline]
    #[allow(clippy::cmp_null)]
    fn hook_free(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[cfg(not(target_vendor = "apple"))]
    #[inline]
    fn hook_memalign(&mut self, alignment: usize, size: usize) -> *mut c_void {
        unsafe { self.allocator.alloc(size, alignment) }
    }

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
    #[cfg(all(not(target_vendor = "apple")))]
    fn hook_malloc_usable_size(&mut self, ptr: *mut c_void) -> usize {
        self.allocator.get_usable_size(ptr)
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPv(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvm(&mut self, ptr: *mut c_void, _ulong: u64) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvmSt11align_val_t(&mut self, ptr: *mut c_void, _ulong: u64, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvRKSt9nothrow_t(&mut self, ptr: *mut c_void, _nothrow: *const c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
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
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdaPvSt11align_val_t(&mut self, ptr: *mut c_void, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPv(&mut self, ptr: *mut c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvm(&mut self, ptr: *mut c_void, _ulong: u64) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvmSt11align_val_t(&mut self, ptr: *mut c_void, _ulong: u64, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvRKSt9nothrow_t(&mut self, ptr: *mut c_void, _nothrow: *const c_void) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[allow(non_snake_case)]
    #[allow(clippy::cmp_null)]
    #[inline]
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
    #[allow(clippy::cmp_null)]
    #[inline]
    fn hook__ZdlPvSt11align_val_t(&mut self, ptr: *mut c_void, _alignment: usize) {
        if ptr != std::ptr::null_mut() {
            unsafe { self.allocator.release(ptr) }
        }
    }

    #[inline]
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
    fn hook_write(&mut self, fd: i32, buf: *const c_void, count: usize) -> usize {
        extern "C" {
            fn write(fd: i32, buf: *const c_void, count: usize) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(buf, count) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "write".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                buf as usize,
                count,
                Backtrace::new(),
            )));
        }
        unsafe { write(fd, buf, count) }
    }

    #[inline]
    fn hook_read(&mut self, fd: i32, buf: *mut c_void, count: usize) -> usize {
        extern "C" {
            fn read(fd: i32, buf: *mut c_void, count: usize) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(buf, count) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "read".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                buf as usize,
                count,
                Backtrace::new(),
            )));
        }
        unsafe { read(fd, buf, count) }
    }

    #[inline]
    fn hook_fgets(&mut self, s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void {
        extern "C" {
            fn fgets(s: *mut c_void, size: u32, stream: *mut c_void) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, size as usize) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "fgets".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                size as usize,
                Backtrace::new(),
            )));
        }
        unsafe { fgets(s, size, stream) }
    }

    #[inline]
    fn hook_memcmp(&mut self, s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        extern "C" {
            fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memcmp(s1, s2, n) }
    }

    #[inline]
    fn hook_memcpy(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memcpy(dest, src, n) }
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    fn hook_mempcpy(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "mempcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "mempcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { mempcpy(dest, src, n) }
    }

    #[inline]
    fn hook_memmove(&mut self, dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
        extern "C" {
            fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memmove".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memmove".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memmove(dest, src, n) }
    }

    #[inline]
    fn hook_memset(&mut self, dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(dest, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "memset".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memset(dest, c, n) }
    }

    #[inline]
    fn hook_memchr(&mut self, s: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memchr(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memchr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memchr(s, c, n) }
    }

    #[inline]
    #[cfg(not(target_vendor = "apple"))]
    fn hook_memrchr(&mut self, s: *mut c_void, c: i32, n: usize) -> *mut c_void {
        extern "C" {
            fn memrchr(s: *mut c_void, c: i32, n: usize) -> *mut c_void;
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memrchr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { memrchr(s, c, n) }
    }

    #[inline]
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
                self.real_address_for_stalked(AsanRuntime::pc()),
                haystack as usize,
                haystacklen,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle, needlelen) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "memmem".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                needle as usize,
                needlelen,
                Backtrace::new(),
            )));
        }
        unsafe { memmem(haystack, haystacklen, needle, needlelen) }
    }

    #[cfg(all(not(target_os = "android")))]
    #[inline]
    fn hook_bzero(&mut self, s: *mut c_void, n: usize) {
        extern "C" {
            fn bzero(s: *mut c_void, n: usize);
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "bzero".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { bzero(s, n) }
    }

    #[cfg(all(not(target_os = "android"), not(target_vendor = "apple")))]
    #[inline]
    fn hook_explicit_bzero(&mut self, s: *mut c_void, n: usize) {
        extern "C" {
            fn explicit_bzero(s: *mut c_void, n: usize);
        }
        if !(self.shadow_check_func.unwrap())(s, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "explicit_bzero".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { explicit_bzero(s, n) }
    }

    #[cfg(all(not(target_os = "android")))]
    #[inline]
    fn hook_bcmp(&mut self, s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
        extern "C" {
            fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "bcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { bcmp(s1, s2, n) }
    }

    #[inline]
    fn hook_strchr(&mut self, s: *mut c_char, c: i32) -> *mut c_char {
        extern "C" {
            fn strchr(s: *mut c_char, c: i32) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strchr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { strchr(s, c) }
    }

    #[inline]
    fn hook_strrchr(&mut self, s: *mut c_char, c: i32) -> *mut c_char {
        extern "C" {
            fn strrchr(s: *mut c_char, c: i32) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strrchr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { strrchr(s, c) }
    }

    #[inline]
    fn hook_strcasecmp(&mut self, s1: *const c_char, s2: *const c_char) -> i32 {
        extern "C" {
            fn strcasecmp(s1: *const c_char, s2: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasecmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcasecmp(s1, s2) }
    }

    #[inline]
    fn hook_strncasecmp(&mut self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        extern "C" {
            fn strncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncasecmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncasecmp(s1, s2, n) }
    }

    #[inline]
    fn hook_strcat(&mut self, s1: *mut c_char, s2: *const c_char) -> *mut c_char {
        extern "C" {
            fn strcat(s1: *mut c_char, s2: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcat".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcat(s1, s2) }
    }

    #[inline]
    fn hook_strcmp(&mut self, s1: *const c_char, s2: *const c_char) -> i32 {
        extern "C" {
            fn strcmp(s1: *const c_char, s2: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { strlen(s1) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                unsafe { strlen(s1) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { strlen(s2) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                unsafe { strlen(s2) },
                Backtrace::new(),
            )));
        }
        unsafe { strcmp(s1, s2) }
    }

    #[inline]
    fn hook_strncmp(&mut self, s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
        extern "C" {
            fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s2 as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncmp(s1, s2, n) }
    }

    #[inline]
    fn hook_strcpy(&mut self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        extern "C" {
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "strcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        unsafe { strcpy(dest, src) }
    }

    #[inline]
    fn hook_strncpy(&mut self, dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
        extern "C" {
            fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "strncpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                n,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, n) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strncpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                n,
                Backtrace::new(),
            )));
        }
        unsafe { strncpy(dest, src, n) }
    }

    #[inline]
    fn hook_stpcpy(&mut self, dest: *mut c_char, src: *const c_char) -> *mut c_char {
        extern "C" {
            fn stpcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(dest as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgWrite((
                "stpcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                dest as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(src as *const c_void, unsafe { strlen(src) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "stpcpy".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                unsafe { strlen(src) },
                Backtrace::new(),
            )));
        }
        unsafe { stpcpy(dest, src) }
    }

    #[inline]
    fn hook_strdup(&mut self, s: *const c_char) -> *mut c_char {
        extern "C" {
            fn strlen(s: *const c_char) -> usize;
            fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char;
        }
        let size = unsafe { strlen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strdup".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
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
    fn hook_strlen(&mut self, s: *const c_char) -> usize {
        extern "C" {
            fn strlen(s: *const c_char) -> usize;
        }
        let size = unsafe { strlen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strlen".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                size,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
    fn hook_strnlen(&mut self, s: *const c_char, n: usize) -> usize {
        extern "C" {
            fn strnlen(s: *const c_char, n: usize) -> usize;
        }
        let size = unsafe { strnlen(s, n) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, size) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strnlen".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                size,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
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
                self.real_address_for_stalked(AsanRuntime::pc()),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle as *const c_void, unsafe { strlen(needle) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strstr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )));
        }
        unsafe { strstr(haystack, needle) }
    }

    #[inline]
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
                self.real_address_for_stalked(AsanRuntime::pc()),
                haystack as usize,
                unsafe { strlen(haystack) },
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(needle as *const c_void, unsafe { strlen(needle) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "strcasestr".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                needle as usize,
                unsafe { strlen(needle) },
                Backtrace::new(),
            )));
        }
        unsafe { strcasestr(haystack, needle) }
    }

    #[inline]
    fn hook_atoi(&mut self, s: *const c_char) -> i32 {
        extern "C" {
            fn atoi(s: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atoi".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atoi(s) }
    }

    #[inline]
    fn hook_atol(&mut self, s: *const c_char) -> i32 {
        extern "C" {
            fn atol(s: *const c_char) -> i32;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atol".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atol(s) }
    }

    #[inline]
    fn hook_atoll(&mut self, s: *const c_char) -> i64 {
        extern "C" {
            fn atoll(s: *const c_char) -> i64;
            fn strlen(s: *const c_char) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s as *const c_void, unsafe { strlen(s) }) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "atoll".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                unsafe { strlen(s) },
                Backtrace::new(),
            )));
        }
        unsafe { atoll(s) }
    }

    #[inline]
    fn hook_wcslen(&mut self, s: *const wchar_t) -> usize {
        extern "C" {
            fn wcslen(s: *const wchar_t) -> usize;
        }
        let size = unsafe { wcslen(s) };
        if !(self.shadow_check_func.unwrap())(s as *const c_void, (size + 1) * 2) {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcslen".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s as usize,
                (size + 1) * 2,
                Backtrace::new(),
            )));
        }
        size
    }

    #[inline]
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
                self.real_address_for_stalked(AsanRuntime::pc()),
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
                self.real_address_for_stalked(AsanRuntime::pc()),
                src as usize,
                (unsafe { wcslen(src) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        unsafe { wcscpy(dest, src) }
    }

    #[inline]
    fn hook_wcscmp(&mut self, s1: *const wchar_t, s2: *const wchar_t) -> i32 {
        extern "C" {
            fn wcscmp(s1: *const wchar_t, s2: *const wchar_t) -> i32;
            fn wcslen(s: *const wchar_t) -> usize;
        }
        if !(self.shadow_check_func.unwrap())(s1 as *const c_void, unsafe { (wcslen(s1) + 1) * 2 })
        {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
                s1 as usize,
                (unsafe { wcslen(s1) } + 1) * 2,
                Backtrace::new(),
            )));
        }
        if !(self.shadow_check_func.unwrap())(s2 as *const c_void, unsafe { (wcslen(s2) + 1) * 2 })
        {
            AsanErrors::get_mut().report_error(AsanError::BadFuncArgRead((
                "wcscmp".to_string(),
                self.real_address_for_stalked(AsanRuntime::pc()),
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
    #[allow(clippy::too_many_lines)]
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

        for libname in ["libc++.so", "libc++.so.1", "libc++_shared.so"] {
            for export in Module::enumerate_exports(libname) {
                match &export.name[..] {
                    "_Znam" => {
                        hook_func!(Some(libname), _Znam, (size: usize), *mut c_void);
                    }
                    "_ZnamRKSt9nothrow_t" => {
                        hook_func!(
                            Some(libname),
                            _ZnamRKSt9nothrow_t,
                            (size: usize, _nothrow: *const c_void),
                            *mut c_void
                        );
                    }
                    "_ZnamSt11align_val_t" => {
                        hook_func!(
                            Some(libname),
                            _ZnamSt11align_val_t,
                            (size: usize, alignment: usize),
                            *mut c_void
                        );
                    }
                    "_ZnamSt11align_val_tRKSt9nothrow_t" => {
                        hook_func!(
                            Some(libname),
                            _ZnamSt11align_val_tRKSt9nothrow_t,
                            (size: usize, alignment: usize, _nothrow: *const c_void),
                            *mut c_void
                        );
                    }
                    "_Znwm" => {
                        hook_func!(Some(libname), _Znwm, (size: usize), *mut c_void);
                    }
                    "_ZnwmRKSt9nothrow_t" => {
                        hook_func!(
                            Some(libname),
                            _ZnwmRKSt9nothrow_t,
                            (size: usize, _nothrow: *const c_void),
                            *mut c_void
                        );
                    }
                    "_ZnwmSt11align_val_t" => {
                        hook_func!(
                            Some(libname),
                            _ZnwmSt11align_val_t,
                            (size: usize, alignment: usize),
                            *mut c_void
                        );
                    }
                    "_ZnwmSt11align_val_tRKSt9nothrow_t" => {
                        hook_func!(
                            Some(libname),
                            _ZnwmSt11align_val_tRKSt9nothrow_t,
                            (size: usize, alignment: usize, _nothrow: *const c_void),
                            *mut c_void
                        );
                    }
                    "_ZdaPv" => {
                        hook_func!(Some(libname), _ZdaPv, (ptr: *mut c_void), ());
                    }
                    "_ZdaPvm" => {
                        hook_func!(Some(libname), _ZdaPvm, (ptr: *mut c_void, _ulong: u64), ());
                    }
                    "_ZdaPvmSt11align_val_t" => {
                        hook_func!(
                            Some(libname),
                            _ZdaPvmSt11align_val_t,
                            (ptr: *mut c_void, _ulong: u64, _alignment: usize),
                            ()
                        );
                    }
                    "_ZdaPvRKSt9nothrow_t" => {
                        hook_func!(
                            Some(libname),
                            _ZdaPvRKSt9nothrow_t,
                            (ptr: *mut c_void, _nothrow: *const c_void),
                            ()
                        );
                    }
                    "_ZdaPvSt11align_val_t" => {
                        hook_func!(
                            Some(libname),
                            _ZdaPvSt11align_val_t,
                            (ptr: *mut c_void, _alignment: usize),
                            ()
                        );
                    }
                    "_ZdaPvSt11align_val_tRKSt9nothrow_t" => {
                        hook_func!(
                            Some(libname),
                            _ZdaPvSt11align_val_tRKSt9nothrow_t,
                            (ptr: *mut c_void, _alignment: usize, _nothrow: *const c_void),
                            ()
                        );
                    }
                    "_ZdlPv" => {
                        hook_func!(Some(libname), _ZdlPv, (ptr: *mut c_void), ());
                    }
                    "_ZdlPvm" => {
                        hook_func!(Some(libname), _ZdlPvm, (ptr: *mut c_void, _ulong: u64), ());
                    }
                    "_ZdlPvmSt11align_val_t" => {
                        hook_func!(
                            Some(libname),
                            _ZdlPvmSt11align_val_t,
                            (ptr: *mut c_void, _ulong: u64, _alignment: usize),
                            ()
                        );
                    }
                    "_ZdlPvRKSt9nothrow_t" => {
                        hook_func!(
                            Some(libname),
                            _ZdlPvRKSt9nothrow_t,
                            (ptr: *mut c_void, _nothrow: *const c_void),
                            ()
                        );
                    }
                    "_ZdlPvSt11align_val_t" => {
                        hook_func!(
                            Some(libname),
                            _ZdlPvSt11align_val_t,
                            (ptr: *mut c_void, _alignment: usize),
                            ()
                        );
                    }
                    "_ZdlPvSt11align_val_tRKSt9nothrow_t" => {
                        hook_func!(
                            Some(libname),
                            _ZdlPvSt11align_val_tRKSt9nothrow_t,
                            (ptr: *mut c_void, _alignment: usize, _nothrow: *const c_void),
                            ()
                        );
                    }
                    _ => {}
                }
            }
        }

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
        self.dump_registers();

        let fault_address = self.regs[17];
        let actual_pc = self.regs[18];

        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        let instructions = cs
            .disasm_count(
                unsafe { std::slice::from_raw_parts(actual_pc as *mut u8, 24) },
                actual_pc as u64,
                3,
            )
            .expect("Failed to disassmeble");

        let insn = instructions.as_ref().first().unwrap(); // This is the very instruction that has triggered fault
        println!("{:#?}", insn);
        let operands = cs.insn_detail(insn).unwrap().arch_detail().operands();

        let mut access_type: Option<RegAccessType> = None;
        let mut regs: Option<(RegId, RegId, i64)> = None;
        for operand in operands {
            if let X86Operand(x86operand) = operand {
                if let X86OperandType::Mem(mem) = x86operand.op_type {
                    access_type = x86operand.access;
                    regs = Some((mem.base(), mem.index(), mem.disp()));
                }
            }
        }

        let backtrace = Backtrace::new();
        let (stack_start, stack_end) = Self::current_stack();

        if let Some(r) = regs {
            let (base_idx, size) = self.register_idx(r.0); // safe to unwrap
            let (index_idx, _) = self.register_idx(r.1);
            let disp = r.2;

            // from capstone register id to self.regs's index
            let base_value = match base_idx {
                Some(base) => match size {
                    Some(sz) => {
                        if sz == 64 {
                            Some(self.regs[base as usize])
                        } else {
                            Some(self.regs[base as usize] & 0xffffffff)
                        }
                    }
                    _ => None,
                },
                _ => None,
            };

            // println!("{:x}", base_value);
            #[allow(clippy::option_if_let_else)]
            let error = if fault_address >= stack_start && fault_address < stack_end {
                match access_type {
                    Some(typ) => match typ {
                        RegAccessType::ReadOnly => AsanError::StackOobRead((
                            self.regs,
                            actual_pc,
                            (base_idx, index_idx, disp as usize, fault_address),
                            backtrace,
                        )),
                        _ => AsanError::StackOobWrite((
                            self.regs,
                            actual_pc,
                            (base_idx, index_idx, disp as usize, fault_address),
                            backtrace,
                        )),
                    },
                    None => AsanError::Unknown((
                        self.regs,
                        actual_pc,
                        (base_idx, index_idx, disp as usize, fault_address),
                        backtrace,
                    )),
                }
            } else if base_value.is_some() {
                if let Some(metadata) = self
                    .allocator
                    .find_metadata(fault_address, base_value.unwrap())
                {
                    match access_type {
                        Some(typ) => {
                            let asan_readwrite_error = AsanReadWriteError {
                                registers: self.regs,
                                pc: actual_pc,
                                fault: (base_idx, index_idx, disp as usize, fault_address),
                                metadata: metadata.clone(),
                                backtrace,
                            };
                            match typ {
                                RegAccessType::ReadOnly => {
                                    if metadata.freed {
                                        AsanError::ReadAfterFree(asan_readwrite_error)
                                    } else {
                                        AsanError::OobRead(asan_readwrite_error)
                                    }
                                }
                                _ => {
                                    if metadata.freed {
                                        AsanError::WriteAfterFree(asan_readwrite_error)
                                    } else {
                                        AsanError::OobWrite(asan_readwrite_error)
                                    }
                                }
                            }
                        }
                        None => AsanError::Unknown((
                            self.regs,
                            actual_pc,
                            (base_idx, index_idx, disp as usize, fault_address),
                            backtrace,
                        )),
                    }
                } else {
                    AsanError::Unknown((
                        self.regs,
                        actual_pc,
                        (base_idx, index_idx, disp as usize, fault_address),
                        backtrace,
                    ))
                }
            } else {
                AsanError::Unknown((
                    self.regs,
                    actual_pc,
                    (base_idx, index_idx, disp as usize, fault_address),
                    backtrace,
                ))
            };
            AsanErrors::get_mut().report_error(error);

            // This is not even a mem instruction??
        } else {
            AsanErrors::get_mut().report_error(AsanError::Unknown((
                self.regs,
                actual_pc,
                (None, None, 0, fault_address),
                backtrace,
            )));
        }

        // self.dump_registers();
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
        let instructions = instructions.iter().collect::<Vec<&Insn>>();
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
                    (
                        Some(base_reg),
                        Some(index_reg),
                        displacement as usize,
                        fault_address,
                    ),
                    backtrace,
                ))
            } else {
                AsanError::StackOobWrite((
                    self.regs,
                    actual_pc,
                    (
                        Some(base_reg),
                        Some(index_reg),
                        displacement as usize,
                        fault_address,
                    ),
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
                fault: (
                    Some(base_reg),
                    Some(index_reg),
                    displacement as usize,
                    fault_address,
                ),
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
                (
                    Some(base_reg),
                    Some(index_reg),
                    displacement as usize,
                    fault_address,
                ),
                backtrace,
            ))
        };
        AsanErrors::get_mut().report_error(error);
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::unused_self)]
    fn register_idx(&self, capid: RegId) -> (Option<u16>, Option<u16>) {
        match capid.0 {
            19 => (Some(0), Some(32)),
            22 => (Some(2), Some(32)),
            24 => (Some(3), Some(32)),
            21 => (Some(1), Some(32)),
            30 => (Some(5), Some(32)),
            20 => (Some(4), Some(32)),
            29 => (Some(6), Some(32)),
            23 => (Some(7), Some(32)),
            226 => (Some(8), Some(32)),
            227 => (Some(9), Some(32)),
            228 => (Some(10), Some(32)),
            229 => (Some(11), Some(32)),
            230 => (Some(12), Some(32)),
            231 => (Some(13), Some(32)),
            232 => (Some(14), Some(32)),
            233 => (Some(15), Some(32)),
            26 => (Some(18), Some(32)),
            35 => (Some(0), Some(64)),
            38 => (Some(2), Some(64)),
            40 => (Some(3), Some(64)),
            37 => (Some(1), Some(64)),
            44 => (Some(5), Some(64)),
            36 => (Some(4), Some(64)),
            43 => (Some(6), Some(64)),
            39 => (Some(7), Some(64)),
            106 => (Some(8), Some(64)),
            107 => (Some(9), Some(64)),
            108 => (Some(10), Some(64)),
            109 => (Some(11), Some(64)),
            110 => (Some(12), Some(64)),
            111 => (Some(13), Some(64)),
            112 => (Some(14), Some(64)),
            113 => (Some(15), Some(64)),
            41 => (Some(18), Some(64)),
            _ => (None, None),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn dump_registers(&self) {
        println!("rax: {:x}", self.regs[0]);
        println!("rbx: {:x}", self.regs[1]);
        println!("rcx: {:x}", self.regs[2]);
        println!("rdx: {:x}", self.regs[3]);
        println!("rbp: {:x}", self.regs[4]);
        println!("rsp: {:x}", self.regs[5]);
        println!("rsi: {:x}", self.regs[6]);
        println!("rdi: {:x}", self.regs[7]);
        println!("r8: {:x}", self.regs[8]);
        println!("r9: {:x}", self.regs[9]);
        println!("r10: {:x}", self.regs[10]);
        println!("r11: {:x}", self.regs[11]);
        println!("r12: {:x}", self.regs[12]);
        println!("r13: {:x}", self.regs[13]);
        println!("r14: {:x}", self.regs[14]);
        println!("r15: {:x}", self.regs[15]);
        println!("instrumented rip: {:x}", self.regs[16]);
        println!("fault address: {:x}", self.regs[17]);
        println!("actual rip: {:x}", self.regs[18]);
    }

    // https://godbolt.org/z/Y87PYGd69
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
                // https://gist.github.com/yantonov/4359090
                // we need 16bit number here, (not 8bit)
                uint16_t val = *(uint16_t *)addr;
                val = (val & 0xff00) >> 8 | (val & 0x00ff) << 8;
                val = (val & 0xf0f0) >> 4 | (val & 0x0f0f) << 4;
                val = (val & 0xcccc) >> 2 | (val & 0x3333) << 2;
                val = (val & 0xaaaa) >> 1 | (val & 0x5555) << 1;
                val = (val >> 8) | (val << 8); // swap the byte
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
    #[allow(clippy::too_many_lines)]
    fn generate_shadow_check_function(&mut self) {
        let shadow_bit = self.allocator.shadow_bit();
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);

        // Rdi start, Rsi size
        dynasm!(ops
        ;       .arch x64
        ;       mov     cl, shadow_bit as i8
        ;       mov     eax, 1
        ;       mov     edx, 1
        ;       shl     rdx, cl
        ;       mov     r10d, 2
        ;       shl     r10, cl
        ;       test    rsi, rsi
        ;       je      >LBB0_15
        ;       mov     rcx, rdi
        ;       shr     rcx, 3
        ;       add     rdx, rcx
        ;       add     r10, -1
        ;       and     r10, rdx
        ;       and     edi, 7
        ;       je      >LBB0_4
        ;       mov     cl, 8
        ;       sub     cl, dil
        ;       cmp     rsi, 8
        ;       movzx   ecx, cl
        ;       mov     r8d, esi
        ;       cmovae  r8d, ecx
        ;       mov     r9d, -1
        ;       mov     ecx, r8d
        ;       shl     r9d, cl
        ;       movzx   ecx, WORD [r10]
        ;       rol     cx, 8
        ;       mov     edx, ecx
        ;       shr     edx, 4
        ;       and     edx, 3855
        ;       shl     ecx, 4
        ;       and     ecx, -3856
        ;       or      ecx, edx
        ;       mov     edx, ecx
        ;       shr     edx, 2
        ;       and     edx, 13107
        ;       and     ecx, -3277
        ;       lea     ecx, [rdx + 4*rcx]
        ;       mov     edx, ecx
        ;       shr     edx, 1
        ;       and     edx, 21845
        ;       and     ecx, -10923
        ;       lea     ecx, [rdx + 2*rcx]
        ;       rol     cx, 8
        ;       movzx   edx, cx
        ;       mov     ecx, edi
        ;       shr     edx, cl
        ;       not     r9d
        ;       movzx   ecx, r9b
        ;       and     edx, ecx
        ;       cmp     edx, ecx
        ;       jne     >LBB0_11
        ;       movzx   ecx, r8b
        ;       sub     rsi, rcx
        ;       add     r10, 1
        ;LBB0_4:
        ;       mov     r8, rsi
        ;       shr     r8, 3
        ;       mov     r9, r8
        ;       and     r9, -8
        ;       mov     edi, r8d
        ;       and     edi, 7
        ;       add     r9, r10
        ;       and     esi, 63
        ;       mov     rdx, r8
        ;       mov     rcx, r10
        ;LBB0_5:
        ;       cmp     rdx, 7
        ;       jbe     >LBB0_8
        ;       add     rdx, -8
        ;       cmp     QWORD [rcx], -1
        ;       lea     rcx, [rcx + 8]
        ;       je      <LBB0_5
        ;       jmp     >LBB0_11
        ;LBB0_8:
        ;       lea     rcx, [8*rdi]
        ;       sub     rsi, rcx
        ;LBB0_9:
        ;       test    rdi, rdi
        ;       je      >LBB0_13
        ;       add     rdi, -1
        ;       cmp     BYTE [r9], -1
        ;       lea     r9, [r9 + 1]
        ;       je      <LBB0_9
        ;LBB0_11:
        ;       xor     eax, eax
        ;       ret
        ;LBB0_13:
        ;       test    rsi, rsi
        ;       je      >LBB0_15
        ;       and     sil, 7
        ;       mov     dl, -1
        ;       mov     ecx, esi
        ;       shl     dl, cl
        ;       not     dl
        ;       mov     cl, BYTE [r8 + r10]
        ;       rol     cl, 4
        ;       mov     eax, ecx
        ;       shr     al, 2
        ;       shl     cl, 2
        ;       and     cl, -52
        ;       or      cl, al
        ;       mov     eax, ecx
        ;       shr     al, 1
        ;       and     al, 85
        ;       add     cl, cl
        ;       and     cl, -86
        ;       or      cl, al
        ;       and     cl, dl
        ;       xor     eax, eax
        ;       cmp     cl, dl
        ;       sete    al
        ;LBB0_15:
        ;       ret
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
            ; .arch aarch64

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

    // https://godbolt.org/z/cqEKf63e1
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

        uint8_t remainder = start & 0b111;
        uint16_t val = *(uint16_t *)addr;
        val = (val & 0xff00) >> 8 | (val & 0x00ff) << 8;
        val = (val & 0xf0f0) >> 4 | (val & 0x0f0f) << 4;
        val = (val & 0xcccc) >> 2 | (val & 0x3333) << 2;
        val = (val & 0xaaaa) >> 1 | (val & 0x5555) << 1;
        val = (val >> 8) | (val << 8); // swap the byte
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
                ;   mov     esi, 2
                ;   shl     rsi, cl
                ;   shr     rdx, 3
                ;   add     rdx, rax
                ;   add     rsi, -1
                ;   and     rsi, rdx
                ;   movzx   eax, WORD [rsi]
                ;   rol     ax, 8
                ;   mov     ecx, eax
                ;   shr     ecx, 4
                ;   and     ecx, 3855
                ;   shl     eax, 4
                ;   and     eax, -3856
                ;   or      eax, ecx
                ;   mov     ecx, eax
                ;   shr     ecx, 2
                ;   and     ecx, 13107
                ;   and     eax, -3277
                ;   lea     eax, [rcx + 4*rax]
                ;   mov     ecx, eax
                ;   shr     ecx, 1
                ;   and     ecx, 21845
                ;   and     eax, -10923
                ;   lea     eax, [rcx + 2*rax]
                ;   rol     ax, 8
                ;   movzx   edx, ax
                ;   and     dil, 7
                ;   mov     ecx, edi
                ;   shr     edx, cl
                ;   mov     cl, BYTE bit as i8
                ;   mov     eax, -1
                ;   shl     eax, cl
                ;   not     eax
                ;   movzx   ecx, al
                ;   and     edx, ecx
                ;   xor     eax, eax
                ;   cmp     edx, ecx
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
            ; mov rdi, [>self_regs_addr] // load self.regs into rdi
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
            ; mov rax, [rsp + 0x10]
            ; mov [rdi + 0x0], rax
            ; mov rcx, [rsp + 0x18]
            ; mov [rdi + 0x10], rcx
            ; mov rdx, [rsp + 0x20]
            ; mov [rdi + 0x18], rdx
            ; mov rsi, [rsp + 0x28]
            ; mov [rdi + 0x30], rsi

            ; mov rsi, [rsp + 0x0]  // access_addr
            ; mov [rdi + 0x88], rsi
            ; mov rsi, [rsp + 0x8] // true_rip
            ; mov [rdi + 0x90], rsi

            ; mov rsi, rdi // we want to save rdi, but we have to copy the address of self.regs into another register
            ; mov rdi, [rsp + 0x30]
            ; mov [rsi + 0x38], rdi

            ; mov rdi, [>self_addr]
            ; mov rsi, [>trap_func]

            // Align the rsp to 16bytes boundary
            // This adds either -8 or -16 to the currrent rsp.
            // rsp is restored later from self.regs
            ; add rsp, -8
            ; and rsp, -16

            ; call rsi

            ; mov rdi, [>self_regs_addr]
            // restore rbx to r15
            ; mov rbx, [rdi + 0x8]
            ; mov rbp, [rdi + 0x20]
            ; mov rsp, [rdi + 0x28]
            ; mov r8, [rdi + 0x40]
            ; mov r9, [rdi + 0x48]
            ; mov r10, [rdi + 0x50]
            ; mov r11, [rdi + 0x58]
            ; mov r12, [rdi + 0x60]
            ; mov r13, [rdi + 0x68]
            ; mov r14, [rdi + 0x70]
            ; mov r15, [rdi + 0x78]
            ; mov rsi, [rdi + 0x80] // load back >done into rsi
            ; jmp rsi

            // Ignore eh_frame_cie for amd64
            // See discussions https://github.com/AFLplusplus/LibAFL/pull/331
            ;->accessed_address:
            ; .dword 0x0
            ; self_addr:
            ; .qword self as *mut _  as *mut c_void as i64
            ; self_regs_addr:
            ; .qword &mut self.regs as *mut _ as *mut c_void as i64
            ; trap_func:
            ; .qword AsanRuntime::handle_trap as *mut c_void as i64
        );
        self.blob_report = Some(ops_report.finalize().unwrap().into_boxed_slice());

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
