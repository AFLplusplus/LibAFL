//! # symbols
//! This module provides implementations symbol lookups. The ability to
//! substitute this functionality may be helpful for targets where
//! conventional symbol lookup is not possible, e.g. if libc is statically
//! linked
use alloc::fmt::Debug;
use core::ffi::{CStr, c_char, c_void};

use thiserror::Error;

use crate::{GuestAddr, patch::Patches};

pub mod atomic_guest_addr;

#[cfg(not(feature = "single-threaded"))]
pub use atomic_guest_addr::multi_threaded::AtomicGuestAddr;
#[cfg(feature = "single-threaded")]
pub use atomic_guest_addr::single_threaded::AtomicGuestAddr;

#[cfg(feature = "libc")]
pub mod dlsym;

pub mod nop;

pub trait Symbols: Debug + Sized + Send {
    type Error: Debug;
    fn lookup(name: *const c_char) -> Result<GuestAddr, Self::Error>;
}

pub trait Function {
    const NAME: &'static CStr;
    type Func: Copy;
}

pub trait SymbolsLookupStr: Symbols {
    fn lookup_str(name: &CStr) -> Result<GuestAddr, Self::Error>;
}

impl<S: Symbols> SymbolsLookupStr for S {
    fn lookup_str(name: &CStr) -> Result<GuestAddr, Self::Error> {
        S::lookup(name.as_ptr() as *const c_char)
    }
}

pub trait FunctionPointer: Function {
    fn as_ptr(addr: GuestAddr) -> Result<Self::Func, FunctionPointerError>;
}

impl<T: Function> FunctionPointer for T {
    fn as_ptr(addr: GuestAddr) -> Result<Self::Func, FunctionPointerError> {
        if addr == GuestAddr::MIN || addr == GuestAddr::MAX {
            Err(FunctionPointerError::BadAddress(addr))?;
        }

        if Patches::is_patched(addr) {
            Err(FunctionPointerError::PatchedAddress(addr))?;
        }

        let pp_sym = (&addr) as *const GuestAddr as *const *mut c_void;
        let p_f = pp_sym as *const Self::Func;
        let f = unsafe { *p_f };
        Ok(f)
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum FunctionPointerError {
    #[error("Bad address: {0}")]
    BadAddress(GuestAddr),
    #[error("Patched address: {0}")]
    PatchedAddress(GuestAddr),
}
