use core::{
    cmp::Ordering,
    slice::{from_raw_parts, from_raw_parts_mut},
};

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, count: usize) {
    let src_slice = unsafe { from_raw_parts(src, count) };
    let dest_slice = unsafe { from_raw_parts_mut(dest, count) };

    if src < dest {
        #[allow(clippy::manual_memcpy)]
        for i in 0..count {
            let idx = count - 1 - i;
            dest_slice[idx] = src_slice[idx];
        }
    } else {
        #[allow(clippy::manual_memcpy)]
        for i in 0..count {
            dest_slice[i] = src_slice[i];
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, count: usize) {
    let src_slice = unsafe { from_raw_parts(src, count) };
    let dest_slice = unsafe { from_raw_parts_mut(dest, count) };
    #[allow(clippy::manual_memcpy)]
    for i in 0..count {
        dest_slice[i] = src_slice[i];
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, value: u8, count: usize) {
    let dest_slice = unsafe { from_raw_parts_mut(dest, count) };
    #[allow(clippy::needless_range_loop)]
    for i in 0..count {
        dest_slice[i] = value;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(ptr1: *const u8, ptr2: *const u8, count: usize) -> i32 {
    let slice1 = unsafe { from_raw_parts(ptr1, count) };
    let slice2 = unsafe { from_raw_parts(ptr2, count) };

    for i in 0..count {
        match slice1[i].cmp(&slice2[i]) {
            Ordering::Equal => (),
            Ordering::Less => return -1,
            Ordering::Greater => return 1,
        }
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(ptr1: *const u8, ptr2: *const u8, count: usize) -> i32 {
    let slice1 = unsafe { from_raw_parts(ptr1, count) };
    let slice2 = unsafe { from_raw_parts(ptr2, count) };

    for i in 0..count {
        if slice1[i] != slice2[i] {
            return 1;
        }
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut i = 0;
    let mut cursor = s;

    unsafe {
        while *cursor != 0 {
            cursor = cursor.offset(1);
            i += 1;
        }
    }

    i
}
