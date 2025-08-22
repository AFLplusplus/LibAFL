#![cfg_attr(not(feature = "test"), no_std)]
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
    tracking::{Tracking, guest_fast::GuestFastTracking},
};
use log::{Level, info, trace};
use spin::{Lazy, mutex::Mutex};

type Syms = DlSymSymbols<LookupTypeNext>;

type GuestMap = LibcMmap<Syms>;

type GuestBackend = MimallocBackend<DlmallocBackend<GuestMap>>;

pub type GuestFrontend =
    DefaultFrontend<GuestBackend, GuestShadow<GuestMap, DefaultShadowLayout>, GuestFastTracking>;

pub type GuestSyms = DlSymSymbols<LookupTypeNext>;

pub type GuestEnv = Env<LibcFileReader<GuestSyms>>;

const PAGE_SIZE: usize = 4096;

static FRONTEND: Lazy<Mutex<GuestFrontend>> = Lazy::new(|| {
    let level = GuestEnv::initialize()
        .ok()
        .and_then(|e| e.log_level())
        .unwrap_or(Level::Warn);
    LibcLogger::initialize::<GuestSyms>(level);
    info!("ASAN Guest initializing...");
    let backend = GuestBackend::new(DlmallocBackend::new(PAGE_SIZE));
    let shadow = GuestShadow::<GuestMap, DefaultShadowLayout>::new().unwrap();
    let tracking = GuestFastTracking::new().unwrap();
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
    for hook in PatchedHooks::default() {
        let target = hook.lookup::<GuestSyms>().unwrap();
        Patches::apply::<RawPatch, GuestMap>(target, hook.destination).unwrap();
    }
    info!("ASAN Guest initialized.");
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
pub unsafe extern "C" fn asan_swap(_enabled: bool) {
    /* Don't log since this function is on the logging path */
}

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: fn() = ctor;

#[unsafe(no_mangle)]
fn ctor() {
    drop(FRONTEND.lock());
}
