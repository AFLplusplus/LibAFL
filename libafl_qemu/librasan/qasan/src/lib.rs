#![no_std]
extern crate alloc;

use core::ffi::{CStr, c_char, c_void};

use asan::{
    GuestAddr,
    allocator::{
        backend::{dlmalloc::DlmallocBackend, mimalloc::MimallocBackend},
        frontend::{AllocatorFrontend, default::DefaultFrontend},
    },
    hooks::PatchedHooks,
    host::{Host, libc::LibcHost},
    logger::libc::LibcLogger,
    maps::{MapReader, libc::LibcMapReader},
    mmap::libc::LibcMmap,
    patch::{Patches, raw::RawPatch},
    shadow::{Shadow, host::HostShadow},
    symbols::{
        Symbols,
        dlsym::{DlSymSymbols, LookupTypeNext},
    },
    tracking::{Tracking, host::HostTracking},
};
use log::{Level, trace};
use spin::{Lazy, Mutex};

type Syms = DlSymSymbols<LookupTypeNext>;

type QasanMmap = LibcMmap<Syms>;

type QasanBackend = MimallocBackend<DlmallocBackend<QasanMmap>>;

type QasanHost = LibcHost<Syms>;

pub type QasanFrontend =
    DefaultFrontend<QasanBackend, HostShadow<QasanHost>, HostTracking<QasanHost>>;

pub type QasanSyms = DlSymSymbols<LookupTypeNext>;

const PAGE_SIZE: usize = 4096;

static FRONTEND: Lazy<Mutex<QasanFrontend>> = Lazy::new(|| {
    LibcLogger::initialize::<QasanSyms>(Level::Info);
    let backend = QasanBackend::new(DlmallocBackend::new(PAGE_SIZE));
    let shadow = HostShadow::<QasanHost>::new().unwrap();
    let tracking = HostTracking::<QasanHost>::new().unwrap();
    let frontend = QasanFrontend::new(
        backend,
        shadow,
        tracking,
        QasanFrontend::DEFAULT_REDZONE_SIZE,
        QasanFrontend::DEFAULT_QUARANTINE_SIZE,
    )
    .unwrap();
    let mappings = LibcMapReader::<QasanSyms>::mappings().unwrap();
    Patches::init(mappings);
    for hook in PatchedHooks::default() {
        let target = hook.lookup::<QasanSyms>().unwrap();
        Patches::apply::<RawPatch, QasanMmap>(target, hook.destination).unwrap();
    }
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
    QasanSyms::lookup(name).unwrap() as *const c_void
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
    QasanHost::swap(enabled).unwrap();
}

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: fn() = ctor;

#[unsafe(no_mangle)]
fn ctor() {
    drop(FRONTEND.lock());
}
