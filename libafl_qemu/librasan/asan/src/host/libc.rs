//! # linux
//! The `LibcHost` supports the established means of interacting with the QEMU
//! emulator on Linux by means of issuing a bespoke syscall via the libc library
use core::{
    ffi::{CStr, c_long},
    marker::PhantomData,
};

use thiserror::Error;

use crate::{
    GuestAddr,
    host::{Host, HostAction},
    shadow::PoisonType,
    symbols::{
        AtomicGuestAddr, Function, FunctionPointer, FunctionPointerError, Symbols, SymbolsLookupStr,
    },
};

#[derive(Debug)]
struct FunctionSyscall;

impl Function for FunctionSyscall {
    type Func = unsafe extern "C" fn(num: c_long, ...) -> c_long;
    const NAME: &'static CStr = c"syscall";
}

#[derive(Debug)]
pub struct LibcHost<S: Symbols> {
    _phantom: PhantomData<S>,
}

impl<S: Symbols> Host for LibcHost<S> {
    type Error = LibcHostError<S>;

    fn load(start: GuestAddr, len: usize) -> Result<(), LibcHostError<S>> {
        unsafe {
            let syscall = Self::get_syscall()?;
            let ret = syscall(Self::SYSCALL_NO, HostAction::CheckLoad as usize, start, len);
            if ret != 0 {
                return Err(LibcHostError::SyscallError(ret));
            }
        }
        Ok(())
    }

    fn store(start: GuestAddr, len: usize) -> Result<(), LibcHostError<S>> {
        unsafe {
            let syscall = Self::get_syscall()?;
            let ret = syscall(
                Self::SYSCALL_NO,
                HostAction::CheckStore as usize,
                start,
                len,
            );
            if ret != 0 {
                return Err(LibcHostError::SyscallError(ret));
            }
        };
        Ok(())
    }

    fn poison(start: GuestAddr, len: usize, val: PoisonType) -> Result<(), LibcHostError<S>> {
        unsafe {
            let syscall = Self::get_syscall()?;
            let ret = syscall(
                Self::SYSCALL_NO,
                HostAction::Poison as usize,
                start,
                len,
                val as usize,
            );
            if ret != 0 {
                return Err(LibcHostError::SyscallError(ret));
            }
        };
        Ok(())
    }

    fn unpoison(start: GuestAddr, len: usize) -> Result<(), LibcHostError<S>> {
        let syscall = Self::get_syscall()?;
        let ret = unsafe { syscall(Self::SYSCALL_NO, HostAction::Unpoison as usize, start, len) };
        if ret != 0 {
            return Err(LibcHostError::SyscallError(ret));
        }
        Ok(())
    }

    fn is_poison(start: GuestAddr, len: usize) -> Result<bool, LibcHostError<S>> {
        let syscall = Self::get_syscall()?;
        let ret = unsafe { syscall(Self::SYSCALL_NO, HostAction::IsPoison as usize, start, len) };
        match ret {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(LibcHostError::SyscallError(ret)),
        }
    }

    fn swap(enabled: bool) -> Result<(), LibcHostError<S>> {
        unsafe {
            let syscall = Self::get_syscall()?;
            let ret = syscall(
                Self::SYSCALL_NO,
                HostAction::SwapState as usize,
                enabled as usize,
            );
            if ret != 0 {
                return Err(LibcHostError::SyscallError(ret));
            }
        };
        Ok(())
    }

    fn track(start: GuestAddr, len: usize) -> Result<(), LibcHostError<S>> {
        unsafe {
            let syscall = Self::get_syscall()?;
            let ret = syscall(Self::SYSCALL_NO, HostAction::Alloc as usize, start, len);
            if ret != 0 {
                return Err(LibcHostError::SyscallError(ret));
            }
        };
        Ok(())
    }

    fn untrack(start: GuestAddr) -> Result<(), LibcHostError<S>> {
        let syscall = Self::get_syscall()?;
        let ret = unsafe { syscall(Self::SYSCALL_NO, HostAction::Dealloc as usize, start) };
        if ret != 0 {
            return Err(LibcHostError::SyscallError(ret));
        }
        Ok(())
    }
}

static SYSCALL_ADDR: AtomicGuestAddr = AtomicGuestAddr::new();

impl<S: Symbols> LibcHost<S> {
    const SYSCALL_NO: c_long = 0xa2a4;

    fn get_syscall() -> Result<<FunctionSyscall as Function>::Func, LibcHostError<S>> {
        let addr = SYSCALL_ADDR.try_get_or_insert_with(|| {
            S::lookup_str(FunctionSyscall::NAME).map_err(|e| LibcHostError::FailedToFindSymbol(e))
        })?;
        let f = FunctionSyscall::as_ptr(addr).map_err(|e| LibcHostError::InvalidPointerType(e))?;
        Ok(f)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum LibcHostError<S: Symbols> {
    #[error("Syscall error: {0:?}")]
    SyscallError(c_long),
    #[error("Failed to find mmap functions")]
    FailedToFindSymbol(S::Error),
    #[error("Invalid pointer type: {0:?}")]
    InvalidPointerType(FunctionPointerError),
}
