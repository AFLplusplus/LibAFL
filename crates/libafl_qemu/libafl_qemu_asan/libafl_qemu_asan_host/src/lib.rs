#![no_std]
extern crate alloc;

use core::ffi::{CStr, c_char, c_void};

use libafl_asan::{
    GuestAddr,
    allocator::{
        backend::dlmalloc::DlmallocBackend,
        frontend::{AllocatorFrontend, default::DefaultFrontend},
    },
    env::Env,
    file::libc::LibcFileReader,
    hooks::PatchedHooks,
    host::{Host, HostAction},
    maps::{Maps, iterator::MapIterator},
    patch::{Patches, raw::RawPatch},
    shadow::{PoisonType, Shadow, host::HostShadow},
    symbols::{
        Symbols,
        dlsym::{DlSymSymbols, LookupTypeNext},
    },
    tracking::{Tracking, host::HostTracking},
};
use log::trace;
use spin::{Lazy, Mutex};

type Syms = DlSymSymbols<LookupTypeNext>;

type HostMmap = MyHostMmap;

type HostBackend = DlmallocBackend<HostMmap>;

type HostInterface = RawHost;

#[derive(Debug, Clone)]
pub struct DummyTracking;
impl Tracking for DummyTracking {
    type Error = libafl::Error;
    fn track(&mut self, _start: GuestAddr, _len: usize) -> Result<(), Self::Error> {
        Ok(())
    }
    fn untrack(&mut self, _start: GuestAddr) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub type HostFontend = DefaultFrontend<HostBackend, HostShadow<HostInterface>, DummyTracking>;

pub type HostSyms = DlSymSymbols<LookupTypeNext>;

pub type HostEnv = Env<LibcFileReader<HostSyms>>;

const PAGE_SIZE: usize = 4096;

use core::slice::{from_raw_parts, from_raw_parts_mut};

use libafl_asan::mmap::{Mmap, MmapProt};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MyHostMmap {
    addr: usize,
    len: usize,
}

impl Mmap for MyHostMmap {
    type Error = libafl::Error;

    fn map(len: usize) -> Result<Self, Self::Error> {
        unsafe { log_msg(b"MyHostMmap::map called\n") };
        let ret = unsafe {
            raw_mmap(
                0,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if ret < 0 {
            unsafe { log_msg(b"MyHostMmap::map failed\n") };
            Err(libafl::Error::unknown("mmap failed"))
        } else {
            unsafe { log_msg(b"MyHostMmap::map success\n") };
            Ok(Self {
                addr: ret as usize,
                len,
            })
        }
    }

    fn map_at(addr: GuestAddr, len: usize) -> Result<Self, Self::Error> {
        unsafe { log_msg(b"MyHostMmap::map_at called\n") };
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_FIXED;

        #[cfg(target_os = "linux")]
        let flags = flags | libc::MAP_FIXED_NOREPLACE;

        let ret = unsafe {
            raw_mmap(
                addr as usize,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if ret < 0 {
            unsafe { log_msg(b"MyHostMmap::map_at failed\n") };
            Err(libafl::Error::unknown("mmap at failed"))
        } else {
            unsafe { log_msg(b"MyHostMmap::map_at success\n") };
            Ok(Self {
                addr: ret as usize,
                len,
            })
        }
    }

    fn protect(addr: GuestAddr, len: usize, prot: MmapProt) -> Result<(), Self::Error> {
        let mut c_prot = 0;
        if prot.contains(MmapProt::READ) {
            c_prot |= libc::PROT_READ;
        }
        if prot.contains(MmapProt::WRITE) {
            c_prot |= libc::PROT_WRITE;
        }
        if prot.contains(MmapProt::EXEC) {
            c_prot |= libc::PROT_EXEC;
        }

        let ret = unsafe { raw_mprotect(addr as usize, len, c_prot) };
        if ret < 0 {
            Err(libafl::Error::unknown("mprotect failed"))
        } else {
            Ok(())
        }
    }

    fn huge_pages(addr: GuestAddr, len: usize) -> Result<(), Self::Error> {
        #[cfg(target_os = "linux")]
        {
            let ret = unsafe { raw_madvise(addr as usize, len, libc::MADV_HUGEPAGE) };
            if ret < 0 {
                return Err(libafl::Error::unknown("madvise hugepage failed"));
            }
        }
        Ok(())
    }

    fn dont_dump(addr: GuestAddr, len: usize) -> Result<(), Self::Error> {
        #[cfg(target_os = "linux")]
        {
            let ret = unsafe { raw_madvise(addr as usize, len, libc::MADV_DONTDUMP) };
            if ret < 0 {
                return Err(libafl::Error::unknown("madvise dontdump failed"));
            }
        }
        Ok(())
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { from_raw_parts(self.addr as *const u8, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self.addr as *mut u8, self.len) }
    }
}

impl Drop for MyHostMmap {
    fn drop(&mut self) {
        unsafe { raw_munmap(self.addr, self.len) };
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_mmap(
    addr: usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: usize,
) -> isize {
    let res: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 9, // SYS_mmap
            in("rdi") addr,
            in("rsi") length,
            in("rdx") prot,
            in("r10") flags,
            in("r8") fd,
            in("r9") offset,
            lateout("rax") res,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    res
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_munmap(addr: usize, length: usize) -> isize {
    let res: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 11, // SYS_munmap
            in("rdi") addr,
            in("rsi") length,
            lateout("rax") res,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    res
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_mprotect(addr: usize, length: usize, prot: i32) -> isize {
    let res: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 10, // SYS_mprotect
            in("rdi") addr,
            in("rsi") length,
            in("rdx") prot,
            lateout("rax") res,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    res
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_madvise(addr: usize, length: usize, advice: i32) -> isize {
    let res: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 28, // SYS_madvise
            in("rdi") addr,
            in("rsi") length,
            in("rdx") advice,
            lateout("rax") res,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
    res
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_mmap(
    _addr: usize,
    _length: usize,
    _prot: i32,
    _flags: i32,
    _fd: i32,
    _offset: usize,
) -> isize {
    -1
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_munmap(_addr: usize, _length: usize) -> isize {
    -1
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_mprotect(_addr: usize, _length: usize, _prot: i32) -> isize {
    -1
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_madvise(_addr: usize, _length: usize, _advice: i32) -> isize {
    -1
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_write(fd: i32, buf: *const u8, count: usize) {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 1, // SYS_write
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") count,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_open(path: *const u8, flags: i32, mode: i32) -> i32 {
    let res: i32;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 2, // SYS_open
            in("rdi") path,
            in("rsi") flags,
            in("rdx") mode,
            lateout("rax") res,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    res
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_close(fd: i32) {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 3, // SYS_close
            in("rdi") fd,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_write(_fd: i32, _buf: *const u8, _count: usize) {}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_open(_path: *const u8, _flags: i32, _mode: i32) -> i32 {
    -1
}
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_close(_fd: i32) {}

unsafe fn log_msg(msg: &[u8]) {
    unsafe {
        /*
        // raw_write(2, msg.as_ptr(), msg.len());
        let fd = raw_open(b"/tmp/asan_debug.log\0".as_ptr(), 1089, 438); // O_WRONLY | O_CREAT | O_APPEND, 0666
        if fd >= 0 {
            raw_write(fd, msg.as_ptr(), msg.len());
            raw_close(fd);
        }
        */
        core::arch::asm!(
            "syscall",
            in("rax") 60, // SYS_exit
            in("rdi") 42,
            options(nostack, noreturn)
        );
    }
}

static FRONTEND: Lazy<Mutex<HostFontend>> = Lazy::new(|| {
    unsafe { log_msg(b"ASAN Host initializing...\n") };
    /*
    let level = HostEnv::initialize()
        .ok()
        .and_then(|e| e.log_level())
        .unwrap_or(Level::Warn);
    LibcLogger::initialize::<HostSyms>(level);
    */
    unsafe { log_msg(b"Logger initialized (skipped)\n") };
    let backend = DlmallocBackend::new(PAGE_SIZE);
    unsafe { log_msg(b"Backend initialized\n") };
    let shadow = HostShadow::<HostInterface>::new().unwrap();
    unsafe { log_msg(b"Shadow initialized\n") };
    let tracking = DummyTracking;
    unsafe { log_msg(b"Tracking initialized\n") };
    unsafe { log_msg(b"Calling HostFrontend::new\n") };
    let frontend = HostFontend::new(
        backend,
        shadow,
        tracking,
        HostFontend::DEFAULT_REDZONE_SIZE,
        HostFontend::DEFAULT_QUARANTINE_SIZE,
    )
    .unwrap();
    unsafe { log_msg(b"HostFrontend::new returned\n") };
    unsafe { log_msg(b"Frontend initialized\n") };
    /*
    let mappings = Maps::new(
        MapIterator::<LibcFileReader<Syms>>::new()
            .unwrap()
            .collect(),
    );
    unsafe { log_msg(b"Maps initialized\n") };
    Patches::init(mappings);
    unsafe { log_msg(b"Patches initialized\n") };
    for hook in PatchedHooks::default() {
        unsafe { log_msg(b"Applying hook...\n") };
        let target = hook.lookup::<HostSyms>().unwrap();
        Patches::apply::<RawPatch, HostMmap>(target, hook.destination).unwrap();
    }
    unsafe { log_msg(b"ASAN Host initialized.\n") };
    */
    Mutex::new(frontend)
});

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_load(addr: *const c_void, size: usize) {
    trace!("load - addr: {:#x}, size: {:#x}", addr as GuestAddr, size);
    if FRONTEND
        .lock()
        .shadow()
        .is_poison(addr as GuestAddr, size)
        .unwrap()
    {
        panic!("Poisoned - addr: {:p}, size: {:#x}", addr, size);
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_store(addr: *const c_void, size: usize) {
    trace!("store - addr: {:#x}, size: {:#x}", addr as GuestAddr, size);
    if FRONTEND
        .lock()
        .shadow()
        .is_poison(addr as GuestAddr, size)
        .unwrap()
    {
        panic!("Poisoned - addr: {:p}, size: {:#x}", addr, size);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_syscall4(no: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let mut res: usize = 0;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") no,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rax") res,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    res
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_syscall4(_no: usize, _a1: usize, _a2: usize, _a3: usize, _a4: usize) -> usize {
    0
}

#[derive(Debug, Clone)]
pub struct RawHost;

impl Host for RawHost {
    type Error = libafl::Error;

    fn load(start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        unsafe {
            raw_syscall4(
                0xa2a4,
                HostAction::CheckLoad as usize,
                start as usize,
                len,
                0,
            );
        }
        Ok(())
    }

    fn store(start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        unsafe {
            raw_syscall4(
                0xa2a4,
                HostAction::CheckStore as usize,
                start as usize,
                len,
                0,
            );
        }
        Ok(())
    }

    fn poison(start: GuestAddr, len: usize, val: PoisonType) -> Result<(), Self::Error> {
        unsafe {
            raw_syscall4(
                0xa2a4,
                HostAction::Poison as usize,
                start as usize,
                len,
                val as usize,
            );
        }
        Ok(())
    }

    fn unpoison(start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        unsafe {
            raw_syscall4(
                0xa2a4,
                HostAction::Unpoison as usize,
                start as usize,
                len,
                0,
            );
        }
        Ok(())
    }

    fn is_poison(start: GuestAddr, len: usize) -> Result<bool, Self::Error> {
        let ret = unsafe {
            raw_syscall4(
                0xa2a4,
                HostAction::IsPoison as usize,
                start as usize,
                len,
                0,
            )
        };
        Ok(ret == 1)
    }

    fn swap(enabled: bool) -> Result<(), Self::Error> {
        unsafe {
            raw_syscall4(
                0xa2a4,
                HostAction::SwapState as usize,
                enabled as usize,
                0,
                0,
            );
        }
        Ok(())
    }

    fn track(start: GuestAddr, len: usize) -> Result<(), Self::Error> {
        unsafe {
            raw_syscall4(0xa2a4, HostAction::Alloc as usize, start as usize, len, 0);
        }
        Ok(())
    }

    fn untrack(start: GuestAddr) -> Result<(), Self::Error> {
        unsafe {
            raw_syscall4(0xa2a4, HostAction::Dealloc as usize, start as usize, 0, 0);
        }
        Ok(())
    }
}

use core::{
    mem::transmute,
    sync::atomic::{AtomicUsize, Ordering},
};

static OWNER: AtomicUsize = AtomicUsize::new(0);
static RECURSION: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn raw_gettid() -> usize {
    let res: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 186, // SYS_gettid
            lateout("rax") res,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    res
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
unsafe fn raw_gettid() -> usize {
    0 // Fallback? Or panic?
}

struct GlobalRecursionGuard {
    recursive: bool,
}

impl GlobalRecursionGuard {
    fn enter() -> Self {
        let tid = unsafe { raw_gettid() };
        loop {
            let owner = OWNER.load(Ordering::Acquire);
            if owner == tid {
                RECURSION.fetch_add(1, Ordering::Relaxed);
                return Self { recursive: true };
            }
            if owner == 0 {
                if OWNER
                    .compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    RECURSION.store(1, Ordering::Relaxed);
                    return Self { recursive: false };
                }
            }
            core::hint::spin_loop();
        }
    }
}

impl Drop for GlobalRecursionGuard {
    fn drop(&mut self) {
        let count = RECURSION.load(Ordering::Relaxed);
        if count > 1 {
            RECURSION.store(count - 1, Ordering::Relaxed);
        } else {
            RECURSION.store(0, Ordering::Relaxed);
            OWNER.store(0, Ordering::Release);
        }
    }
}

static mut REAL_MALLOC: Option<unsafe extern "C" fn(usize) -> *mut c_void> = None;
static mut REAL_FREE: Option<unsafe extern "C" fn(*mut c_void)> = None;

const BOOTSTRAP_SIZE: usize = 4096 * 16;
static mut BOOTSTRAP_HEAP: [u8; BOOTSTRAP_SIZE] = [0; BOOTSTRAP_SIZE];
static mut BOOTSTRAP_OFFSET: usize = 0;

unsafe fn get_real_malloc() -> unsafe extern "C" fn(usize) -> *mut c_void {
    if let Some(m) = REAL_MALLOC {
        return m;
    }
    unsafe {
        let malloc_ptr = libc::dlsym(libc::RTLD_NEXT, b"malloc\0".as_ptr() as *const _);
        if !malloc_ptr.is_null() {
            let m: unsafe extern "C" fn(usize) -> *mut c_void = transmute(malloc_ptr);
            REAL_MALLOC = Some(m);
            m
        } else {
            panic!("Could not find real malloc");
        }
    }
}

unsafe fn get_real_free() -> unsafe extern "C" fn(*mut c_void) {
    if let Some(f) = REAL_FREE {
        return f;
    }
    unsafe {
        let free_ptr = libc::dlsym(libc::RTLD_NEXT, b"free\0".as_ptr() as *const _);
        if !free_ptr.is_null() {
            let f: unsafe extern "C" fn(*mut c_void) = transmute(free_ptr);
            REAL_FREE = Some(f);
            f
        } else {
            panic!("Could not find real free");
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_alloc(size: usize) -> *mut c_void {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 60, // SYS_exit
            in("rdi") 43,
            options(nostack, noreturn)
        );
    }
    let mut guard = GlobalRecursionGuard::enter();

    if guard.recursive {
        unsafe {
            let real_malloc = REAL_MALLOC;
            if let Some(real_malloc) = real_malloc {
                return real_malloc(size);
            } else {
                let align = 16;
                let heap_ptr = core::ptr::addr_of_mut!(BOOTSTRAP_HEAP) as *mut u8;
                let ptr = heap_ptr.add(BOOTSTRAP_OFFSET);
                let addr = ptr as usize;
                let aligned_addr = (addr + align - 1) & !(align - 1);
                let padding = aligned_addr - addr;
                if BOOTSTRAP_OFFSET + padding + size > BOOTSTRAP_SIZE {
                    return core::ptr::null_mut();
                }
                BOOTSTRAP_OFFSET += padding + size;
                return aligned_addr as *mut c_void;
            }
        }
    }

    unsafe {
        let real_malloc = REAL_MALLOC;
        if real_malloc.is_none() {
            get_real_malloc();
        }

        let align = 16;
        FRONTEND.lock().alloc(size, align).unwrap_or(0) as *mut c_void
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_dealloc(addr: *const c_void) {
    unsafe {
        if addr.is_null() {
            return;
        }

        let addr_val = addr as usize;
        let bootstrap_start = core::ptr::addr_of!(BOOTSTRAP_HEAP) as usize;
        let bootstrap_end = bootstrap_start + BOOTSTRAP_SIZE;
        if addr_val >= bootstrap_start && addr_val < bootstrap_end {
            return;
        }
    }

    let guard = GlobalRecursionGuard::enter();

    if guard.recursive {
        unsafe {
            let real_free = REAL_FREE;
            if let Some(real_free) = real_free {
                real_free(addr as *mut c_void);
            }
        }
        return;
    }

    unsafe {
        let real_free = REAL_FREE;
        if real_free.is_none() {
            get_real_free();
        }

        let mut frontend = FRONTEND.lock();
        let handled = if frontend.get_size(addr as GuestAddr).is_ok() {
            frontend.dealloc(addr as GuestAddr).unwrap();
            true
        } else {
            false
        };

        if !handled {
            let real_free = REAL_FREE;
            if let Some(real_free) = real_free {
                real_free(addr as *mut c_void);
            }
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_get_size(addr: *const c_void) -> usize {
    let guard = GlobalRecursionGuard::enter();
    if guard.recursive {
        return 0;
    }

    unsafe { FRONTEND.lock().get_size(addr as GuestAddr).unwrap_or(0) }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_sym(name: *const c_char) -> *const c_void {
    unsafe { HostSyms::lookup_raw(name).unwrap() as *const c_void }
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
    trace!("track - addr: {:p}, len: {:#x}", addr, len);
    FRONTEND
        .lock()
        .tracking_mut()
        .track(addr as GuestAddr, len)
        .unwrap();
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_untrack(addr: *const c_void) {
    trace!("untrack - addr: {:p}", addr);
    FRONTEND
        .lock()
        .tracking_mut()
        .untrack(addr as GuestAddr)
        .unwrap();
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
pub unsafe extern "C" fn asan_swap(enabled: bool) {
    /* Don't log since this function is on the logging path */
    HostInterface::swap(enabled).unwrap();
}

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: fn() = ctor;

#[unsafe(no_mangle)]
fn ctor() {
    drop(FRONTEND.lock());
}
