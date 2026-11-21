use core::ffi::{c_int, c_void};

use log::trace;
use rustix::{
    fd::BorrowedFd,
    mm::{MapFlags, ProtFlags, mmap as rmmap, mmap_anonymous},
};

use crate::{GuestAddr, asan_track, asan_unpoison, off_t, size_t};

#[cfg(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "xtensa",
))]
const MAP_ANONYMOUS: u32 = 0x0800;
#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "xtensa",
)))]
const MAP_ANONYMOUS: u32 = 0x0020;
const MAP_FAILED: *mut c_void = GuestAddr::MAX as *mut c_void;
const MMAP2_PAGE_MASK: u64 = 0xfff;

/// # Safety
/// See man pages
#[cfg_attr(not(feature = "libc"), unsafe(export_name = "patch_mmap"))]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: size_t,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: off_t,
) -> *mut c_void {
    unsafe {
        trace!(
            "mmap - addr: {addr:p}, len: {len:#x}, prot: {prot:#x}, flags: {flags:#x}, fd: {fd:#x}, offset: {offset:#x}"
        );
        if (offset as u64) & MMAP2_PAGE_MASK != 0 {
            return MAP_FAILED;
        }
        let mmap_prot = ProtFlags::from_bits_retain(prot as u32);
        let raw_flags = flags as u32;
        let mapped = if raw_flags & MAP_ANONYMOUS != 0 {
            mmap_anonymous(
                addr,
                len,
                mmap_prot,
                MapFlags::from_bits_retain(raw_flags & !MAP_ANONYMOUS),
            )
        } else if fd < 0 || offset < 0 {
            return MAP_FAILED;
        } else {
            let file = BorrowedFd::borrow_raw(fd);
            rmmap(
                addr,
                len,
                mmap_prot,
                MapFlags::from_bits_retain(raw_flags),
                file,
                offset as u64,
            )
        };
        if let Ok(map) = mapped {
            asan_unpoison(map, len);
            asan_track(map, len);
            map
        } else {
            MAP_FAILED
        }
    }
}
