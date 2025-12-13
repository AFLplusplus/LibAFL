#![no_std]
extern crate alloc;

use core::ffi::{CStr, c_char, c_void};

use libafl_asan::{
    GuestAddr,
    allocator::{
        backend::{dlmalloc::DlmallocBackend, mimalloc::MimallocBackend},
        frontend::{AllocatorFrontend, default::DefaultFrontend},
    },
    env::Env,
    file::libc::LibcFileReader,
    hooks::PatchedHooks,
    host::{Host, libc::LibcHost},
    logger::libc::LibcLogger,
    maps::{Maps, iterator::MapIterator},
    mmap::libc::LibcMmap,
    patch::{Patches, raw::RawPatch},
    shadow::{Shadow, host::HostShadow},
    symbols::{
        Symbols,
        dlsym::{DlSymSymbols, LookupTypeNext},
    },
    tracking::{Tracking, host::HostTracking},
};
use log::{Level, info, trace};
use spin::{Lazy, Mutex};

type Syms = DlSymSymbols<LookupTypeNext>;

type HostMmap = LibcMmap<Syms>;

type HostBackend = MimallocBackend<DlmallocBackend<HostMmap>>;

type HostInterface = LibcHost<Syms>;

pub type HostFontend =
    DefaultFrontend<HostBackend, HostShadow<HostInterface>, HostTracking<HostInterface>>;

pub type HostSyms = DlSymSymbols<LookupTypeNext>;

pub type HostEnv = Env<LibcFileReader<HostSyms>>;

const PAGE_SIZE: usize = 4096;

static FRONTEND: Lazy<Mutex<HostFontend>> = Lazy::new(|| {
    let level = HostEnv::initialize()
        .ok()
        .and_then(|e| e.log_level())
        .unwrap_or(Level::Warn);
    LibcLogger::initialize::<HostSyms>(level);
    info!("ASAN Host initializing...");
    let backend = HostBackend::new(DlmallocBackend::new(PAGE_SIZE));
    let shadow = HostShadow::<HostInterface>::new().unwrap();
    let tracking = HostTracking::<HostInterface>::new().unwrap();
    let frontend = HostFontend::new(
        backend,
        shadow,
        tracking,
        HostFontend::DEFAULT_REDZONE_SIZE,
        HostFontend::DEFAULT_QUARANTINE_SIZE,
    )
    .unwrap();
    let mappings = Maps::new(
        MapIterator::<LibcFileReader<Syms>>::new()
            .unwrap()
            .collect(),
    );
    Patches::init(mappings);
    for hook in PatchedHooks::default() {
        let target = hook.lookup::<HostSyms>().unwrap();
        Patches::apply::<RawPatch, HostMmap>(target, hook.destination).unwrap();
    }
    info!("ASAN Host initialized.");
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
