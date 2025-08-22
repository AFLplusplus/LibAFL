use core::{
    ffi::{CStr, c_char, c_int},
    marker::PhantomData,
};

use libc::{O_NONBLOCK, O_RDONLY};
use log::trace;
use thiserror::Error;

use crate::{
    asan_swap,
    maps::MapReader,
    size_t, ssize_t,
    symbols::{
        AtomicGuestAddr, Function, FunctionPointer, FunctionPointerError, Symbols, SymbolsLookupStr,
    },
};

#[derive(Debug)]
struct FunctionOpen;

impl Function for FunctionOpen {
    type Func = unsafe extern "C" fn(*const c_char, c_int, c_int) -> c_int;
    const NAME: &'static CStr = c"open";
}

#[derive(Debug)]
struct FunctionClose;

impl Function for FunctionClose {
    type Func = unsafe extern "C" fn(c_int) -> c_int;
    const NAME: &'static CStr = c"close";
}

#[derive(Debug)]
struct FunctionRead;

impl Function for FunctionRead {
    type Func = unsafe extern "C" fn(c_int, *mut c_char, size_t) -> ssize_t;
    const NAME: &'static CStr = c"read";
}

#[derive(Debug)]
struct FunctionErrnoLocation;

impl Function for FunctionErrnoLocation {
    type Func = unsafe extern "C" fn() -> *mut c_int;
    const NAME: &'static CStr = c"__errno_location";
}

static OPEN_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static CLOSE_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static READ_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static GET_ERRNO_LOCATION_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();

#[derive(Debug)]
pub struct LibcMapReader<S: Symbols> {
    fd: c_int,
    phantom: PhantomData<S>,
}

impl<S: Symbols> LibcMapReader<S> {
    fn get_open() -> Result<<FunctionOpen as Function>::Func, LibcMapReaderError<S>> {
        let addr = OPEN_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionOpen::NAME).map_err(|e| LibcMapReaderError::FailedToFindSymbol(e))
        })?;
        let f =
            FunctionOpen::as_ptr(addr).map_err(|e| LibcMapReaderError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_close() -> Result<<FunctionClose as Function>::Func, LibcMapReaderError<S>> {
        let addr = CLOSE_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionClose::NAME)
                .map_err(|e| LibcMapReaderError::FailedToFindSymbol(e))
        })?;
        let f =
            FunctionClose::as_ptr(addr).map_err(|e| LibcMapReaderError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_read() -> Result<<FunctionRead as Function>::Func, LibcMapReaderError<S>> {
        let addr = READ_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionRead::NAME).map_err(|e| LibcMapReaderError::FailedToFindSymbol(e))
        })?;
        let f =
            FunctionRead::as_ptr(addr).map_err(|e| LibcMapReaderError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_errno_location()
    -> Result<<FunctionErrnoLocation as Function>::Func, LibcMapReaderError<S>> {
        let addr = GET_ERRNO_LOCATION_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionErrnoLocation::NAME)
                .map_err(|e| LibcMapReaderError::FailedToFindSymbol(e))
        })?;
        let f = FunctionErrnoLocation::as_ptr(addr)
            .map_err(|e| LibcMapReaderError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn errno() -> Result<c_int, LibcMapReaderError<S>> {
        unsafe { asan_swap(false) };
        let errno_location = Self::get_errno_location()?;
        unsafe { asan_swap(true) };
        let errno = unsafe { *errno_location() };
        Ok(errno)
    }
}

impl<S: Symbols> MapReader for LibcMapReader<S> {
    type Error = LibcMapReaderError<S>;

    fn new() -> Result<LibcMapReader<S>, LibcMapReaderError<S>> {
        let fn_open = Self::get_open()?;
        unsafe { asan_swap(false) };
        let fd = unsafe {
            fn_open(
                c"/proc/self/maps".as_ptr() as *const c_char,
                O_NONBLOCK | O_RDONLY,
                0,
            )
        };
        unsafe { asan_swap(true) };
        if fd < 0 {
            let errno = Self::errno().unwrap();
            return Err(LibcMapReaderError::FailedToOpen(errno));
        }
        Ok(LibcMapReader {
            fd,
            phantom: PhantomData,
        })
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let fn_read = Self::get_read()?;
        unsafe { asan_swap(false) };
        let ret = unsafe { fn_read(self.fd, buf.as_mut_ptr() as *mut c_char, buf.len()) };
        unsafe { asan_swap(true) };
        if ret < 0 {
            let errno = Self::errno().unwrap();
            return Err(LibcMapReaderError::FailedToRead(self.fd, errno));
        }
        Ok(ret as usize)
    }
}

impl<S: Symbols> Drop for LibcMapReader<S> {
    fn drop(&mut self) {
        let fn_close = Self::get_close().unwrap();
        unsafe { asan_swap(false) };
        let ret = unsafe { fn_close(self.fd) };
        unsafe { asan_swap(true) };
        if ret < 0 {
            let errno = Self::errno().unwrap();
            panic!("Failed to close: {}, Errno: {}", self.fd, errno);
        }
        trace!("Closed fd: {}", self.fd);
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum LibcMapReaderError<S: Symbols> {
    #[error("Failed to find mmap functions")]
    FailedToFindSymbol(S::Error),
    #[error("Invalid pointer type: {0:?}")]
    InvalidPointerType(FunctionPointerError),
    #[error("Failed to read - fd: {0}, errno: {1}")]
    FailedToRead(c_int, c_int),
    #[error("Failed to open - errno: {0}")]
    FailedToOpen(c_int),
}
