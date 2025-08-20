use core::{
    ffi::{CStr, c_char, c_int},
    marker::PhantomData,
};

use libc::{O_NONBLOCK, O_RDONLY};
use log::trace;
use thiserror::Error;

use crate::{
    asan_swap,
    file::FileReader,
    size_t, ssize_t,
    symbols::{AtomicGuestAddr, Function, FunctionPointer, FunctionPointerError, Symbols},
};

#[derive(Debug)]
struct FunctionOpen;

impl Function for FunctionOpen {
    const NAME: &CStr = c"open";
    type Func = unsafe extern "C" fn(*const c_char, c_int, c_int) -> c_int;
}

#[derive(Debug)]
struct FunctionClose;

impl Function for FunctionClose {
    const NAME: &CStr = c"close";
    type Func = unsafe extern "C" fn(c_int) -> c_int;
}

#[derive(Debug)]
struct FunctionRead;

impl Function for FunctionRead {
    const NAME: &CStr = c"read";
    type Func = unsafe extern "C" fn(c_int, *mut c_char, size_t) -> ssize_t;
}

#[derive(Debug)]
struct FunctionErrnoLocation;

impl Function for FunctionErrnoLocation {
    const NAME: &CStr = c"__errno_location";
    type Func = unsafe extern "C" fn() -> *mut c_int;
}

static OPEN_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static CLOSE_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static READ_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();
static GET_ERRNO_LOCATION_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();

#[derive(Debug)]
pub struct LibcFileReader<S: Symbols> {
    fd: c_int,
    phantom: PhantomData<S>,
}

impl<S: Symbols> LibcFileReader<S> {
    fn get_open() -> Result<<FunctionOpen as Function>::Func, LibcFileReaderError<S>> {
        let addr = OPEN_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionOpen::NAME).map_err(|e| LibcFileReaderError::FailedToFindSymbol(e))
        })?;
        let f =
            FunctionOpen::as_ptr(addr).map_err(|e| LibcFileReaderError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_close() -> Result<<FunctionClose as Function>::Func, LibcFileReaderError<S>> {
        let addr = CLOSE_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionClose::NAME).map_err(|e| LibcFileReaderError::FailedToFindSymbol(e))
        })?;
        let f =
            FunctionClose::as_ptr(addr).map_err(|e| LibcFileReaderError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_read() -> Result<<FunctionRead as Function>::Func, LibcFileReaderError<S>> {
        let addr = READ_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionRead::NAME).map_err(|e| LibcFileReaderError::FailedToFindSymbol(e))
        })?;
        let f =
            FunctionRead::as_ptr(addr).map_err(|e| LibcFileReaderError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn get_errno_location()
    -> Result<<FunctionErrnoLocation as Function>::Func, LibcFileReaderError<S>> {
        let addr = GET_ERRNO_LOCATION_ADDR.try_get_or_insert_with(|| {
            S::lookup(FunctionErrnoLocation::NAME)
                .map_err(|e| LibcFileReaderError::FailedToFindSymbol(e))
        })?;
        let f = FunctionErrnoLocation::as_ptr(addr)
            .map_err(|e| LibcFileReaderError::InvalidPointerType(e))?;
        Ok(f)
    }

    fn errno() -> Result<c_int, LibcFileReaderError<S>> {
        unsafe { asan_swap(false) };
        let errno_location = Self::get_errno_location()?;
        unsafe { asan_swap(true) };
        let errno = unsafe { *errno_location() };
        Ok(errno)
    }
}

impl<S: Symbols> FileReader for LibcFileReader<S> {
    type Error = LibcFileReaderError<S>;
    fn new(path: &CStr) -> Result<LibcFileReader<S>, Self::Error> {
        let fn_open = Self::get_open()?;
        unsafe { asan_swap(false) };
        let fd = unsafe { fn_open(path.as_ptr() as *const c_char, O_NONBLOCK | O_RDONLY, 0) };
        unsafe { asan_swap(true) };
        if fd < 0 {
            let errno = Self::errno().unwrap();
            return Err(LibcFileReaderError::FailedToOpen(errno));
        }
        Ok(LibcFileReader {
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
            return Err(LibcFileReaderError::FailedToRead(self.fd, errno));
        }
        Ok(ret as usize)
    }
}

impl<S: Symbols> Drop for LibcFileReader<S> {
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
pub enum LibcFileReaderError<S: Symbols> {
    #[error("Failed to find mmap functions")]
    FailedToFindSymbol(S::Error),
    #[error("Invalid pointer type: {0:?}")]
    InvalidPointerType(FunctionPointerError),
    #[error("Failed to read - fd: {0}, errno: {1}")]
    FailedToRead(c_int, c_int),
    #[error("Failed to open - errno: {0}")]
    FailedToOpen(c_int),
}
