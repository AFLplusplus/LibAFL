use core::{
    ffi::{CStr, c_char, c_void},
    sync::atomic::{AtomicBool, Ordering},
};

use log::{Level, error, trace};
use spin::{Lazy, Mutex};

use crate::{
    GuestAddr,
    allocator::{
        backend::dlmalloc::DlmallocBackend,
        frontend::{AllocatorFrontend, default::DefaultFrontend},
    },
    exit::exit,
    shadow::Shadow,
    symbols::Symbols,
    tracking::Tracking,
};

#[cfg(not(feature = "libc"))]
type TestSyms = crate::symbols::nop::NopSymbols;

#[cfg(feature = "libc")]
type TestSyms = crate::symbols::dlsym::DlSymSymbols<crate::symbols::dlsym::LookupTypeNext>;

#[cfg(all(feature = "linux", not(feature = "libc")))]
type TestMap = crate::mmap::linux::LinuxMmap;

#[cfg(feature = "libc")]
type TestMap = crate::mmap::libc::LibcMmap<TestSyms>;

#[cfg(all(feature = "libc", not(feature = "guest"), feature = "host"))]
type TestHost = crate::host::libc::LibcHost<TestSyms>;

#[cfg(all(
    feature = "linux",
    not(feature = "libc"),
    not(feature = "guest"),
    feature = "host"
))]
type TestHost = crate::host::linux::LinuxHost;

#[cfg(feature = "guest")]
type TestShadow =
    crate::shadow::guest::GuestShadow<TestMap, crate::shadow::guest::DefaultShadowLayout>;

#[cfg(feature = "guest")]
type TestTracking = crate::tracking::guest::GuestTracking;

#[cfg(all(not(feature = "guest"), feature = "host"))]
type TestTracking = crate::tracking::host::HostTracking<TestHost>;

#[cfg(all(not(feature = "guest"), feature = "host"))]
type TestShadow = crate::shadow::host::HostShadow<TestHost>;

#[cfg(feature = "libc")]
use crate::logger::libc::LibcLogger;
#[cfg(all(feature = "linux", not(feature = "libc")))]
use crate::logger::linux::LinuxLogger;

pub type TestFrontend = DefaultFrontend<DlmallocBackend<TestMap>, TestShadow, TestTracking>;

const PAGE_SIZE: usize = 4096;

static FRONTEND: Lazy<Mutex<TestFrontend>> = Lazy::new(|| {
    #[cfg(all(feature = "linux", not(feature = "libc")))]
    LinuxLogger::initialize(Level::Info);
    #[cfg(feature = "libc")]
    LibcLogger::initialize::<TestSyms>(Level::Info);
    let backend = DlmallocBackend::<TestMap>::new(PAGE_SIZE);
    let shadow = TestShadow::new().unwrap();
    let tracking = TestTracking::new().unwrap();
    let frontend = TestFrontend::new(
        backend,
        shadow,
        tracking,
        TestFrontend::DEFAULT_REDZONE_SIZE,
        TestFrontend::DEFAULT_QUARANTINE_SIZE,
    )
    .unwrap();
    Mutex::new(frontend)
});

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_load(addr: *const c_void, size: usize) {
    trace!("load - addr: 0x{:x}, size: {:#x}", addr as GuestAddr, size);
    if FRONTEND
        .lock()
        .shadow()
        .is_poison(addr as GuestAddr, size)
        .unwrap()
    {
        panic!("Poisoned - addr: {:p}, size: 0x{:x}", addr, size);
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_store(addr: *const c_void, size: usize) {
    trace!("store - addr: 0x{:x}, size: {:#x}", addr as GuestAddr, size);
    if FRONTEND
        .lock()
        .shadow()
        .is_poison(addr as GuestAddr, size)
        .unwrap()
    {
        panic!("Poisoned - addr: {:p}, size: 0x{:x}", addr, size);
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_alloc(len: usize, align: usize) -> *mut c_void {
    trace!("alloc - len: {:#x}, align: {:#x}", len, align);
    let ptr = FRONTEND.lock().alloc(len, align).unwrap() as *mut c_void;
    trace!(
        "alloc - len: {:#x}, align: {:#x}, ptr: {:p}",
        len, align, ptr
    );
    ptr
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_dealloc(addr: *const c_void) {
    trace!("free - addr: {:p}", addr);
    FRONTEND.lock().dealloc(addr as GuestAddr).unwrap();
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
    TestSyms::lookup(name).unwrap() as *const c_void
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

static EXPECT_PANIC: AtomicBool = AtomicBool::new(false);

pub fn expect_panic() {
    EXPECT_PANIC.store(true, Ordering::SeqCst);
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_panic(msg: *const c_char) -> ! {
    trace!("panic - msg: {:p}", msg);
    let msg = unsafe { CStr::from_ptr(msg as *const c_char) };
    error!("{}", msg.to_str().unwrap());
    match EXPECT_PANIC.load(Ordering::SeqCst) {
        true => {
            exit(0);
        }
        false => {
            panic!("unexpected panic");
        }
    }
}

#[unsafe(no_mangle)]
/// # Safety
pub unsafe extern "C" fn asan_swap(enabled: bool) {
    trace!("swap - enabled: {}", enabled);
}
