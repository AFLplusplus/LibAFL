//! # dlsym
//! This module performs symbol lookup using the `dlsym` function. It supports
//! two variants:
//! - LookupTypeDefault: This performs the lookup using
//!   `dlsym(RTLD_DEFAULT, name)`
//! - LookupTypeNext: This performs the lookup using
//!   `dlsym(RTLD_NEXT, name)`
use alloc::{ffi::NulError, fmt::Debug};
use core::{
    ffi::{CStr, c_char, c_void},
    marker::PhantomData,
};

use libc::{RTLD_DEFAULT, RTLD_NEXT, dlerror, dlsym};
use thiserror::Error;

use crate::{GuestAddr, symbols::Symbols};

pub trait LookupType: Debug + Send {
    const HANDLE: *mut c_void;
}

#[derive(Debug)]
pub struct LookupTypeDefault;
impl LookupType for LookupTypeDefault {
    const HANDLE: *mut c_void = RTLD_DEFAULT;
}

#[derive(Debug, Eq, PartialEq)]
pub struct LookupTypeNext;
impl LookupType for LookupTypeNext {
    const HANDLE: *mut c_void = RTLD_NEXT;
}

#[derive(Debug, Eq, PartialEq)]
pub struct DlSymSymbols<L: LookupType> {
    phantom: PhantomData<L>,
}

impl<L: LookupType> Symbols for DlSymSymbols<L> {
    type Error = DlSymSymbolsError;

    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    unsafe fn lookup_raw(name: *const c_char) -> Result<GuestAddr, Self::Error> {
        if name.is_null() {
            Err(DlSymSymbolsError::NullName())?;
        }
        let p_sym = unsafe { dlsym(L::HANDLE, name) };
        if p_sym.is_null() {
            Err(DlSymSymbolsError::FailedToFindFunction(
                name,
                Self::get_error(),
            ))
        } else {
            Ok(p_sym as GuestAddr)
        }
    }
}

impl Default for DlSymSymbols<LookupTypeDefault> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: LookupType> DlSymSymbols<L> {
    const UNKNOWN_ERROR: &str = "Unknown error";

    pub const fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    fn get_error() -> &'static str {
        let error = unsafe { dlerror() };
        if error.is_null() {
            Self::UNKNOWN_ERROR
        } else {
            unsafe {
                CStr::from_ptr(error)
                    .to_str()
                    .unwrap_or(Self::UNKNOWN_ERROR)
            }
        }
    }
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum DlSymSymbolsError {
    #[error("Bad function name: {0:?}")]
    BadFunctionName(#[from] NulError),
    #[error("Failed to find function: {0:p}, error: {1}")]
    FailedToFindFunction(*const c_char, &'static str),
    #[error("Null name")]
    NullName(),
}
