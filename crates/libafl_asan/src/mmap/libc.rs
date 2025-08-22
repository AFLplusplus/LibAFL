//! # libc
//! This implementation of `Mmap` uses the `libc` crate and hence the standard
//! `libc` library for allocating pages. It should therefore support most
//! operating systems which provide a `libc` library. But is no suited to
//! applications where the library has been statically linked.
use core::{
    cmp::Ordering,
    ffi::{CStr, c_int, c_void},
    marker::PhantomData,
    ptr::null_mut,
    slice::{from_raw_parts, from_raw_parts_mut},
};

#[cfg(target_os = "linux")]
use libc::{MADV_DONTDUMP, MADV_HUGEPAGE};
use libc::{PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE, off_t, size_t};
use log::trace;
use thiserror::Error;

use crate::{
    GuestAddr, asan_swap,
    mmap::{Mmap, MmapProt},
    symbols::{AtomicGuestAddr, Function, FunctionPointer, FunctionPointerError, Symbols},
};

#[derive(Debug)]
struct FunctionMmap;

impl Function for FunctionMmap {
    type Func =
        unsafe extern "C" fn(*mut c_void, size_t, c_int, c_int, c_int, off_t) -> *mut c_void;
    const NAME: &'static CStr = c"mmap";
}

#[derive(Debug)]
struct FunctionMunmap;

impl Function for FunctionMunmap {
    type Func = unsafe extern "C" fn(*mut c_void, size_t) -> c_int;
    const NAME: &'static CStr = c"munmap";
}

#[derive(Debug)]
struct FunctionMprotect;

impl Function for FunctionMprotect {
    type Func = unsafe extern "C" fn(*mut c_void, size_t, c_int) -> c_int;
    const NAME: &'static CStr = c"mprotect";
}

#[derive(Debug)]
struct FunctionErrnoLocation;

impl Function for FunctionErrnoLocation {
    type Func = unsafe extern "C" fn() -> *mut c_int;
    const NAME: &'static CStr = c"__errno_location";
}

#[derive(Debug)]
pub struct FunctionMadvise;

impl Function for FunctionMadvise {
    type Func = unsafe extern "C" fn(*mut c_void, size_t, c_int) -> c_int;
    const NAME: &'static CStr = c"madvise";
}

#[derive(Debug)]
pub struct LibcMmap<S: Symbols> {
    addr: GuestAddr,
    len: usize,
    phantom: PhantomData<S>,
}

impl<S: Symbols> Ord for LibcMmap<S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.addr.cmp(&other.addr)
    }
}

impl<S: Symbols> PartialOrd for LibcMmap<S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<S: Symbols> PartialEq for LibcMmap<S> {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl<S: Symbols> Eq for LibcMmap<S> {}

static MMAP_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static MUNMAP_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static MPROTECT_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static GET_ERRNO_LOCATION_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static MADVISE_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();

impl<S: Symbols> LibcMmap<S> {
    fn get_mmap() -> Result<<FunctionMmap as Function>::Func, LibcMapError<S>> {
        let addr = MMAP_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionMmap::NAME).map_err(|e| LibcMapError::FailedToFindSymbol(e))
        })?;
        let f = FunctionMmap::as_ptr(addr).map_err(|e| LibcMapError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_munmap() -> Result<<FunctionMunmap as Function>::Func, LibcMapError<S>> {
        let addr = MUNMAP_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionMunmap::NAME).map_err(|e| LibcMapError::FailedToFindSymbol(e))
        })?;
        let f = FunctionMunmap::as_ptr(addr).map_err(|e| LibcMapError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_mprotect() -> Result<<FunctionMprotect as Function>::Func, LibcMapError<S>> {
        let addr = MPROTECT_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionMprotect::NAME).map_err(|e| LibcMapError::FailedToFindSymbol(e))
        })?;
        let f = FunctionMprotect::as_ptr(addr).map_err(|e| LibcMapError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_errno_location() -> Result<<FunctionErrnoLocation as Function>::Func, LibcMapError<S>> {
        let addr = GET_ERRNO_LOCATION_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionErrnoLocation::NAME).map_err(|e| LibcMapError::FailedToFindSymbol(e))
        })?;
        let f =
            FunctionErrnoLocation::as_ptr(addr).map_err(|e| LibcMapError::InvalidPointerType(e))?;
        Ok(f)
    }

    pub fn get_madvise() -> Result<<FunctionMadvise as Function>::Func, LibcMapError<S>> {
        let addr = MADVISE_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionMadvise::NAME).map_err(|e| LibcMapError::FailedToFindSymbol(e))
        })?;
        let f = FunctionMadvise::as_ptr(addr).map_err(|e| LibcMapError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn errno() -> Result<c_int, LibcMapError<S>> {
        unsafe { asan_swap(false) };
        let errno_location = Self::get_errno_location()?;
        unsafe { asan_swap(true) };
        let errno = unsafe { *errno_location() };
        Ok(errno)
    }
}

impl<S: Symbols> Mmap for LibcMmap<S> {
    type Error = LibcMapError<S>;

    fn map(len: usize) -> Result<LibcMmap<S>, LibcMapError<S>> {
        let fn_mmap = Self::get_mmap()?;
        unsafe { asan_swap(false) };
        let map = unsafe {
            fn_mmap(
                null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        unsafe { asan_swap(true) };
        if map == libc::MAP_FAILED {
            let errno = Self::errno()?;
            Err(LibcMapError::FailedToMap(len, errno))
        } else {
            let addr = map as GuestAddr;
            Ok(LibcMmap {
                addr,
                len,
                phantom: PhantomData,
            })
        }
    }

    fn map_at(addr: GuestAddr, len: usize) -> Result<LibcMmap<S>, LibcMapError<S>> {
        let fn_mmap = Self::get_mmap()?;
        unsafe { asan_swap(false) };
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_FIXED;

        #[cfg(target_os = "linux")]
        let flags = flags | libc::MAP_FIXED_NOREPLACE;

        let map = unsafe {
            fn_mmap(
                addr as *mut c_void,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        unsafe { asan_swap(true) };
        trace!("Mapped: {:#x}-{:#x}", addr, addr + len);
        if map == libc::MAP_FAILED {
            let errno = Self::errno()?;
            Err(LibcMapError::FailedToMapAt(addr, len, errno))
        } else {
            Ok(LibcMmap {
                addr,
                len,
                phantom: PhantomData,
            })
        }
    }

    fn protect(addr: GuestAddr, len: usize, prot: MmapProt) -> Result<(), Self::Error> {
        trace!("protect - addr: {addr:#x}, len: {len:#x}, prot: {prot:#x}",);
        let fn_mprotect = Self::get_mprotect()?;
        unsafe { asan_swap(false) };
        let ret = unsafe { fn_mprotect(addr as *mut c_void, len, c_int::from(&prot)) };
        unsafe { asan_swap(true) };
        if ret != 0 {
            let errno = Self::errno()?;
            Err(LibcMapError::FailedToMprotect(addr, len, prot, errno))?;
        }

        Ok(())
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { from_raw_parts(self.addr as *const u8, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self.addr as *mut u8, self.len) }
    }

    #[cfg(not(target_os = "linux"))]
    fn huge_pages(_addr: GuestAddr, _len: usize) -> Result<(), Self::Error> {
        unimplemented!();
    }

    #[cfg(target_os = "linux")]
    fn huge_pages(addr: GuestAddr, len: usize) -> Result<(), Self::Error> {
        trace!("huge_pages - addr: {addr:#x}, len: {len:#x}");
        let fn_madvise = Self::get_madvise()?;
        unsafe { asan_swap(false) };
        let ret = unsafe { fn_madvise(addr as *mut c_void, len, MADV_HUGEPAGE) };
        unsafe { asan_swap(true) };
        if ret != 0 {
            let errno = Self::errno()?;
            Err(LibcMapError::FailedToMadviseHugePage(addr, len, errno))?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn dont_dump(_addr: GuestAddr, _len: usize) -> Result<(), Self::Error> {
        unimplemented!()
    }

    #[cfg(target_os = "linux")]
    fn dont_dump(addr: GuestAddr, len: usize) -> Result<(), Self::Error> {
        trace!("dont_dump - addr: {addr:#x}, len: {len:#x}");
        let fn_madvise = Self::get_madvise()?;
        unsafe { asan_swap(false) };
        let ret = unsafe { fn_madvise(addr as *mut c_void, len, MADV_DONTDUMP) };
        unsafe { asan_swap(true) };
        if ret != 0 {
            let errno = Self::errno()?;
            Err(LibcMapError::FailedToMadviseDontDump(addr, len, errno))?;
        }
        Ok(())
    }
}

impl From<&MmapProt> for c_int {
    fn from(prot: &MmapProt) -> Self {
        let mut ret = PROT_NONE;
        if prot.contains(MmapProt::READ) {
            ret |= PROT_READ;
        }
        if prot.contains(MmapProt::WRITE) {
            ret |= PROT_WRITE;
        }
        if prot.contains(MmapProt::EXEC) {
            ret |= PROT_EXEC;
        }
        ret
    }
}

impl<S: Symbols> Drop for LibcMmap<S> {
    fn drop(&mut self) {
        let fn_munmap = Self::get_munmap().unwrap();
        unsafe { asan_swap(false) };
        let ret = unsafe { fn_munmap(self.addr as *mut c_void, self.len) };
        unsafe { asan_swap(true) };
        if ret < 0 {
            let errno = Self::errno().unwrap();
            panic!("Errno: {errno:}");
        }
        trace!("Unmapped: {:#x}-{:#x}", self.addr, self.addr + self.len);
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum LibcMapError<S: Symbols> {
    #[error("Failed to map - len: {0}, errno: {1}")]
    FailedToMap(usize, c_int),
    #[error("Failed to map: {0}, len: {1}, errno: {2}")]
    FailedToMapAt(GuestAddr, usize, c_int),
    #[error("Failed to find mmap functions")]
    FailedToFindSymbol(S::Error),
    #[error("Failed to mprotect - addr: {0}, len: {1}, prot: {2:?}, errno: {3}")]
    FailedToMprotect(GuestAddr, usize, MmapProt, c_int),
    #[error("Invalid pointer type: {0:?}")]
    InvalidPointerType(FunctionPointerError),
    #[error("Failed to madvise HUGEPAGE - addr: {0}, len: {1}, errno: {2}")]
    FailedToMadviseHugePage(GuestAddr, usize, c_int),
    #[error("Failed to madvise DONTDUMP - addr: {0}, len: {1}, errno: {2}")]
    FailedToMadviseDontDump(GuestAddr, usize, c_int),
}
