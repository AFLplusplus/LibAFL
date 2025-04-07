//! # tracking
//! This module is responsible for supporting memory tracking. By logging the
//! ranges of memory being allocated and freed by the target application, we
//! can detect double-free defects.
use alloc::fmt::Debug;

use crate::GuestAddr;

#[cfg(feature = "guest")]
pub mod guest;
#[cfg(feature = "host")]
pub mod host;

pub trait Tracking: Sized + Debug + Send {
    type Error: Debug;
    fn track(&mut self, start: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn untrack(&mut self, start: GuestAddr) -> Result<(), Self::Error>;
}
