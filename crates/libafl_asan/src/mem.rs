use core::mem::transmute;

use nostd_musl::{bcmp, memcmp, memcpy, memmove, memset, strlen};

#[cfg(all(feature = "global_allocator", feature = "dlmalloc"))]
use crate::allocator::backend::dlmalloc::DlmallocBackend;

#[cfg(all(
    feature = "global_allocator",
    feature = "linux",
    target_os = "linux",
    not(feature = "libc")
))]
type Mmap = crate::mmap::linux::LinuxMmap;

#[cfg(all(feature = "global_allocator", feature = "libc",))]
type Mmap = crate::mmap::libc::LibcMmap<
    crate::symbols::dlsym::DlSymSymbols<crate::symbols::dlsym::LookupTypeNext>,
>;

#[cfg(all(feature = "global_allocator", feature = "dlmalloc"))]
const PAGE_SIZE: usize = 4096;

#[global_allocator]
#[cfg(all(
    feature = "global_allocator",
    feature = "dlmalloc",
    not(feature = "mimalloc")
))]
static GLOBAL_ALLOCATOR: DlmallocBackend<Mmap> = DlmallocBackend::new(PAGE_SIZE);

#[global_allocator]
#[cfg(all(
    feature = "global_allocator",
    feature = "dlmalloc",
    feature = "mimalloc"
))]
static GLOBAL_ALLOCATOR: baby_mimalloc::MimallocMutexWrapper<DlmallocBackend<Mmap>> =
    baby_mimalloc::MimallocMutexWrapper::with_os_allocator(DlmallocBackend::new(PAGE_SIZE));

/*
 * The functions are only called from our C code, but we need to tell Rust that
 * we still need it even though it isn't referenced from rust.
 */
#[used]
static LINK_BCMP: unsafe extern "C" fn() = unsafe { transmute(bcmp as *const ()) };

#[used]
static LINK_MEMCMP: unsafe extern "C" fn() = unsafe { transmute(memcmp as *const ()) };

#[used]
static LINK_MEMCPY: unsafe extern "C" fn() = unsafe { transmute(memcpy as *const ()) };

#[used]
static LINK_MEMMOVE: unsafe extern "C" fn() = unsafe { transmute(memmove as *const ()) };

#[used]
static LINK_MEMSET: unsafe extern "C" fn() = unsafe { transmute(memset as *const ()) };

#[used]
static LINK_STRLEN: unsafe extern "C" fn() = unsafe { transmute(strlen as *const ()) };
