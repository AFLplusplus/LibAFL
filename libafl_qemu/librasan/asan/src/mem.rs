#[cfg(all(feature = "global_allocator", feature = "dlmalloc"))]
use crate::allocator::backend::dlmalloc::DlmallocBackend;

#[cfg(all(feature = "global_allocator", feature = "linux", not(feature = "libc")))]
type Mmap = crate::mmap::linux::LinuxMmap;

#[cfg(feature = "libc")]
type Mmap = crate::mmap::libc::LibcMmap<
    crate::symbols::dlsym::DlSymSymbols<crate::symbols::dlsym::LookupTypeNext>,
>;

#[cfg(all(feature = "global_allocator"))]
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
