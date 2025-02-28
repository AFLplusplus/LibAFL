//! # patch
//! This module provides implementations patching function prologues in order
//! to re-direct execution to an alternative address.
use alloc::fmt::Debug;

use crate::GuestAddr;

#[cfg(feature = "hooks")]
pub mod hooks;

pub mod raw;

pub trait Patch: Debug {
    type Error: Debug;
    fn patch(target: GuestAddr, destination: GuestAddr) -> Result<(), Self::Error>;
}
