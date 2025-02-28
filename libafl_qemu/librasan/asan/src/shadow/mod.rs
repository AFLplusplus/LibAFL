//! # shadow
//! This module provides implementations for tracking memory by means of a
//! shadow map. QEMU currently supports two modes of operation for this:
//! - `guest` - This newer mode (made possible by more recent versions of QEMU
//!   supporting the `MAP_NORESERVE` flag to mmap much more efficiently) creates
//!   the shadow maps in the guest memory space and augments the TCG code emit
//!   instructions to test these maps when performing load/store operations.
//! - `host` - This is the original mode whereby the shadow maps are created by
//!   QEMU itself (and hence live in the host's memory space). In this mode, the
//!   TCG code is augmented with calls back into the host in order to validate the
//!   memory being accessed during load/store operations. Note that this requires
//!   the guest memory addresses being used by the TCG code to be converted into
//!   host addresses to be tested against the shadow maps (incurring a performance
//!   overhead) as well as placing constraints on register usage.
use core::fmt::Debug;

use crate::GuestAddr;

#[cfg(feature = "guest")]
pub mod guest;
#[cfg(feature = "host")]
pub mod host;

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum PoisonType {
    AsanValid = 0x00,
    AsanPartial1 = 0x01,
    AsanPartial2 = 0x02,
    AsanPartial3 = 0x03,
    AsanPartial4 = 0x04,
    AsanPartial5 = 0x05,
    AsanPartial6 = 0x06,
    AsanPartial7 = 0x07,
    AsanArrayCookie = 0xac,
    AsanStackRz = 0xf0,
    AsanStackLeftRz = 0xf1,
    AsanStackMidRz = 0xf2,
    AsanStackRightRz = 0xf3,
    AsanStackFreed = 0xf5,
    AsanStackOoscope = 0xf8,
    AsanGlobalRz = 0xf9,
    AsanHeapRz = 0xe9,
    AsanUser = 0xf7,
    AsanHeapLeftRz = 0xfa,
    AsanHeapRightRz = 0xfb,
    AsanHeapFreed = 0xfd,
}

pub trait Shadow: Sized + Debug + Send {
    type Error: Debug;
    fn load(&self, start: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn store(&self, start: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn poison(&mut self, start: GuestAddr, len: usize, val: PoisonType) -> Result<(), Self::Error>;
    fn unpoison(&mut self, start: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn is_poison(&self, start: GuestAddr, len: usize) -> Result<bool, Self::Error>;
}
