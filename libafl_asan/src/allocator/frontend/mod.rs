//! # frontend
//! The frontend of the allocator is responsible for applying the value-added
//! asan features on behalf of incoming user requests for allocations including
//! red-zones, poisoning and memory tracking.
use alloc::fmt::Debug;

use crate::GuestAddr;

pub mod default;

pub trait AllocatorFrontend: Sized + Send {
    type Error: Debug;
    fn alloc(&mut self, len: usize, align: usize) -> Result<GuestAddr, Self::Error>;
    fn dealloc(&mut self, addr: GuestAddr) -> Result<(), Self::Error>;
    fn get_size(&self, addr: GuestAddr) -> Result<usize, Self::Error>;
}
