#![feature(thread_local)]
#![cfg_attr(not(feature = "test"), no_std)]
extern crate alloc;
extern crate libc;

use core::ffi::{CStr, c_char, c_void};
use core::arch::asm;

use libafl_asan::{
    GuestAddr,
    allocator::{
        backend::dlmalloc::DlmallocBackend,
        frontend::{AllocatorFrontend, default::DefaultFrontend},
    },
    env::Env,
    file::libc::LibcFileReader,
    // hooks::PatchedHooks,
    logger::libc::LibcLogger,
    maps::{Maps, iterator::MapIterator},
    mmap::libc::LibcMmap,
    patch::{Patches, raw::RawPatch},
    shadow::{
        Shadow,
        guest::{DefaultShadowLayout, GuestShadow},
    },
    symbols::{
        Symbols,
        dlsym::{DlSymSymbols, LookupTypeNext},
    },
    tracking::{Tracking, guest::GuestTracking},
};
use log::{Level, info, trace};
use spin::{Lazy, mutex::Mutex};

#[global_allocator]
static GLOBAL: DlmallocBackend<GuestMap> = DlmallocBackend::new(4096);

#[thread_local]
static mut IN_ASAN: bool = false;

type Syms = DlSymSymbols<LookupTypeNext>;

type GuestMap = LibcMmap<Syms>;

type GuestBackend = DlmallocBackend<GuestMap>;

pub type GuestFrontend =
    DefaultFrontend<GuestBackend, GuestShadow<GuestMap, DefaultShadowLayout>, GuestTracking>;

pub type GuestSyms = DlSymSymbols<LookupTypeNext>;

pub type GuestEnv = Env<LibcFileReader<GuestSyms>>;

const PAGE_SIZE: usize = 4096;

static FRONTEND: Lazy<Mutex<GuestFrontend>> = Lazy::new(|| {
    let level = GuestEnv::initialize()
        .ok()
        .and_then(|e| e.log_level())
        .unwrap_or(Level::Warn);
    LibcLogger::initialize::<GuestSyms>(level);
    let msg = c"ASAN: Logger initialized\n";
    let msg = c"ASAN: Logger initialized\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    info!("ASAN Guest initializing...");
    let backend = GuestBackend::new(PAGE_SIZE);
    let shadow = GuestShadow::<GuestMap, DefaultShadowLayout>::new().unwrap();
    let tracking = GuestTracking::new().unwrap();
    let frontend = GuestFrontend::new(
        backend,
        shadow,
        tracking,
        GuestFrontend::DEFAULT_REDZONE_SIZE,
        GuestFrontend::DEFAULT_QUARANTINE_SIZE,
    )
    .unwrap();
    let mappings = Maps::new(
        MapIterator::<LibcFileReader<Syms>>::new()
            .unwrap()
            .collect(),
    );
    Patches::init(mappings);
    let msg = c"ASAN: Patches init done\n";
    let msg = c"ASAN: Patches init done\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    // for hook in PatchedHooks::default() {
    //     let target = hook.lookup::<GuestSyms>().unwrap();
    //     if target == hook.destination {
    //         let msg = c"ASAN: Skipping self-patch\n";
    //         unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    //         continue;
    //     }
    //     Patches::apply::<RawPatch, GuestMap>(target, hook.destination).unwrap();
    // }
    
    // Explicitly patch libc malloc to ensure it's hooked even if LD_PRELOAD fails to override
    // unsafe {
    //     let libc_name = c"libc.so.6";
    //     let handle = libc::dlopen(libc_name.as_ptr(), libc::RTLD_LAZY);
    //     if !handle.is_null() {
    //         // ... patching removed to avoid deadlock ...
    //     }
    // }

    info!("ASAN Guest initialized.");
    Mutex::new(frontend)
});

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_load(addr: *const c_void, size: usize) {
    let msg = c"ASAN: Load\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe {
        if FRONTEND
        .lock()
        .shadow()
        .is_poison(addr as GuestAddr, size)
        .unwrap_or(false)
    {
        // panic!("Poisoned - addr: {:p}, size: {:#x}", addr, size);
        // log::error!("Poisoned load - addr: {:p}, size: {:#x}", addr, size);
        unsafe {
            let msg = c"ASAN: Poisoned load\n";
            raw_write(1, msg.as_ptr() as *const _, msg.count_bytes());
            *(0 as *mut u8) = 0; // Abort
        }
    }
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_store(addr: *const c_void, size: usize) {
    let msg = c"ASAN: Store\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe {
        if FRONTEND
        .lock()
        .shadow()
        .is_poison(addr as GuestAddr, size)
        .unwrap_or(false)
    {
        // panic!("Poisoned - addr: {:p}, size: {:#x}", addr, size);
        // log::error!("Poisoned store - addr: {:p}, size: {:#x}", addr, size);
        unsafe {
            let msg = c"ASAN: Poisoned store\n";
            raw_write(1, msg.as_ptr() as *const _, msg.count_bytes());
            *(0 as *mut u8) = 0; // Abort
        }
    }
    }
}

#[inline(always)]
unsafe fn raw_write(fd: i32, buf: *const u8, count: usize) {
    unsafe { raw_syscall(1, fd as u64, buf as u64, count as u64, 0); }
}

#[inline(always)]
unsafe fn log_to_file_raw(msg: &CStr) {
    // x86_64 syscalls: open=2, write=1, close=3
    // flags: O_WRONLY(1) | O_CREAT(64) | O_APPEND(1024) = 1089
    // mode: 0666 = 438
    let path = c"/tmp/asan_debug_raw.log";
    let fd = raw_syscall(2, path.as_ptr() as u64, 1089, 438, 0);
    if fd as i64 > 0 {
        raw_syscall(1, fd, msg.as_ptr() as u64, msg.count_bytes() as u64, 0);
        raw_syscall(3, fd, 0, 0, 0);
    } else {
        // Fallback to stderr if open fails
        raw_syscall(1, 2, msg.as_ptr() as u64, msg.count_bytes() as u64, 0);
    }
}

unsafe fn raw_syscall(sys_num: i32, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    #[cfg(target_arch = "x86_64")]
    asm!(
        "syscall",
        in("rax") sys_num,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        in("r10") arg4,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("rax") ret,
        clobber_abi("system")
    );
    ret
}

const QASAN_FAKESYS_NR: i32 = 0xa2a4;

#[repr(u64)]
enum QasanAction {
    Alloc = 6,
    Dealloc = 7,
    Enable = 8,
}

#[unsafe(export_name = "asan_alloc")]
/// # Safety
pub unsafe extern "C" fn asan_alloc(size: usize, align: usize) -> *mut c_void {
    let msg = c"ASAN: Alloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe {
        if IN_ASAN {
            let msg = c"ASAN: Alloc (fallback)\n";
            raw_write(2, msg.as_ptr() as *const _, msg.count_bytes());
            // Fallback to mmap
            let mut mmap_size = size;
            if align > 4096 {
                mmap_size += align;
            }
            // Round up to page size
            mmap_size = (mmap_size + 4095) & !4095;
            
            let ptr = libc::mmap(
                core::ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return core::ptr::null_mut();
            }
            return ptr;
        }
        IN_ASAN = true;
    }
    let ret = match FRONTEND.lock().alloc(size, align) {
        Ok(ptr) => {
            unsafe { raw_syscall(QASAN_FAKESYS_NR, QasanAction::Alloc as u64, ptr as u64, size as u64, 0); }
            ptr as *mut c_void
        }
        Err(_) => {
            let msg = c"ASAN: Alloc failed\n";
            unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
            unsafe { *(0 as *mut u8) = 0; } // Abort
            core::ptr::null_mut()
        }
    };
    unsafe {
        IN_ASAN = false;
    }
    ret
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_dealloc(ptr: *mut c_void) {
    let msg = c"ASAN: Dealloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe {
        if IN_ASAN {
            return;
        }
        IN_ASAN = true;
    }
    FRONTEND.lock().dealloc(ptr as GuestAddr).unwrap();
    unsafe { raw_syscall(QASAN_FAKESYS_NR, QasanAction::Dealloc as u64, ptr as u64, 0, 0); }
    unsafe {
        IN_ASAN = false;
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_get_size(addr: *const c_void) -> usize {
    trace!("get_size - addr: {:p}", addr);
    FRONTEND.lock().get_size(addr as GuestAddr).unwrap()
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_sym(name: *const c_char) -> *const c_void {
    unsafe { GuestSyms::lookup_raw(name).unwrap() as *const c_void }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_page_size() -> usize {
    PAGE_SIZE
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_unpoison(addr: *const c_void, len: usize) {
    trace!("unpoison - addr: {:p}, len: {:#x}", addr, len);
    FRONTEND
        .lock()
        .shadow_mut()
        .unpoison(addr as GuestAddr, len)
        .unwrap();
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_track(addr: *const c_void, len: usize) {
    // trace!("track - addr: {:p}, len: {:#x}", addr, len);
    if unsafe { IN_ASAN } {
        return;
    }
    FRONTEND
        .lock()
        .tracking_mut()
        .track(addr as GuestAddr, len)
        .unwrap();
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_untrack(addr: *const c_void) {
    // trace!("untrack - addr: {:p}", addr);
    let _ = FRONTEND
        .lock()
        .tracking_mut()
        .untrack(addr as GuestAddr);
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_panic(msg: *const c_char) -> ! {
    trace!("panic - msg: {:p}", msg);
    let msg = unsafe { CStr::from_ptr(msg as *const c_char) };
    panic!("{}", msg.to_str().unwrap());
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_swap(_enabled: bool) {
    /* Don't log since this function is on the logging path */
}

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: unsafe extern "C" fn() = ctor;

#[unsafe(no_mangle)]
unsafe extern "C" fn ctor() {
    let msg = c"ASAN: ctor\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    // unsafe {
    //     IN_ASAN = true;
    // }
    // drop(FRONTEND.lock());
    // unsafe {
    //     IN_ASAN = false;
    // }
    let msg = c"ASAN: Patches applied\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe {
        raw_syscall(QASAN_FAKESYS_NR, QasanAction::Enable as u64, 0, 0, 0);
    }
    let msg = c"ASAN: ctor end\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
}

#[unsafe(link_section = ".init_array")]
#[used]
static CTOR: unsafe extern "C" fn() = ctor;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    let msg = c"ASAN: malloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    // unsafe { *(0 as *mut u8) = 0; } // Force crash
    unsafe { asan_alloc(size, 16) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let msg = c"ASAN: calloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    let total_size = nmemb * size;
    let ptr = unsafe { asan_alloc(total_size, 16) };
    if !ptr.is_null() {
        unsafe { libc::memset(ptr, 0, total_size); }
    }
    ptr
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let msg = c"ASAN: realloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    if ptr.is_null() {
        return unsafe { asan_alloc(size, 16) };
    }
    if size == 0 {
        unsafe { asan_dealloc(ptr); }
        return core::ptr::null_mut();
    }
    let old_size = unsafe { asan_get_size(ptr) };
    let new_ptr = unsafe { asan_alloc(size, 16) };
    if !new_ptr.is_null() {
        let copy_size = if old_size < size { old_size } else { size };
        unsafe { libc::memcpy(new_ptr, ptr, copy_size); }
        unsafe { asan_dealloc(ptr); }
    }
    new_ptr
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    let msg = c"ASAN: free\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    if ptr.is_null() {
        return;
    }
    unsafe { asan_dealloc(ptr); }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_malloc(size: usize) -> *mut c_void {
    let msg = c"ASAN: __libc_malloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    unsafe { malloc(size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_calloc(nmemb: usize, size: usize) -> *mut c_void {
    let msg = c"ASAN: __libc_calloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    unsafe { calloc(nmemb, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let msg = c"ASAN: __libc_realloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    unsafe { realloc(ptr, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_free(ptr: *mut c_void) {
    let msg = c"ASAN: __libc_free\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    unsafe { free(ptr) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    let msg = c"ASAN: memalign\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    unsafe { asan_alloc(size, alignment) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_memalign(alignment: usize, size: usize) -> *mut c_void {
    let msg = c"ASAN: __libc_memalign\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    unsafe { memalign(alignment, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    let msg = c"ASAN: aligned_alloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    unsafe { memalign(alignment, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_memalign(memptr: *mut *mut c_void, alignment: usize, size: usize) -> i32 {
    let msg = c"ASAN: posix_memalign\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    let ptr = unsafe { memalign(alignment, size) };
    if ptr.is_null() {
        return 12; // ENOMEM
    }
    unsafe { *memptr = ptr; }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    let msg = c"ASAN: valloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    unsafe { memalign(4096, size) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut c_void {
    let msg = c"ASAN: pvalloc\n";
    unsafe { raw_write(2, msg.as_ptr() as *const _, msg.count_bytes()); }
    unsafe { log_to_file_raw(msg); }
    let size = (size + 4095) & !4095;
    unsafe { memalign(4096, size) }
}
