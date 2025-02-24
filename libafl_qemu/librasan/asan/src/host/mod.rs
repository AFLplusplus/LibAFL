//! # host
//! The host module is responsible for interacting with the emulator hosting the
//! target. It provides an abstraction to allow alternative implementations to
//! be used in the event a different emulator is used, or if the target
//! application is for a different operating system, then the interface for
//! interacting the host may be different.
use core::fmt::Debug;

use crate::{shadow::PoisonType, GuestAddr};

#[cfg(feature = "libc")]
pub mod libc;

#[cfg(feature = "linux")]
pub mod linux;

#[repr(usize)]
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
enum HostAction {
    CheckLoad,
    CheckStore,
    Poison,
    UserPoison,
    Unpoison,
    IsPoison,
    Alloc,
    Dealloc,
    Enable,
    Disable,
    SwapState,
}

pub trait Host: Debug + Send {
    type Error: Debug;
    fn load(start: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn store(start: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn poison(start: GuestAddr, len: usize, val: PoisonType) -> Result<(), Self::Error>;
    fn unpoison(start: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn is_poison(start: GuestAddr, len: usize) -> Result<bool, Self::Error>;
    fn swap(enabled: bool) -> Result<(), Self::Error>;
    fn alloc(start: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn dealloc(start: GuestAddr) -> Result<(), Self::Error>;
}
