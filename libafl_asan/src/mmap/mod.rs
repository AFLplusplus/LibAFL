//! # mmap
//! This module provides implementations for creating memory mappings. This is
//! used by the guest shadow implementation and can also be used by allocator
//! backends.
use alloc::fmt::{self, Debug, Formatter};

use bitflags::bitflags;

use crate::GuestAddr;

#[cfg(feature = "libc")]
pub mod libc;

#[cfg(all(feature = "linux", target_os = "linux"))]
pub mod linux;

bitflags! {
    #[derive(PartialEq, Eq)]
    pub struct MmapProt: u32 {
        const READ = 0;
        const WRITE = 1;
        const EXEC = 2;
    }
}

impl Debug for MmapProt {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            if self.contains(MmapProt::READ) {
                "r"
            } else {
                "-"
            }
        )?;
        write!(
            f,
            "{}",
            if self.contains(MmapProt::WRITE) {
                "w"
            } else {
                "-"
            }
        )?;
        write!(
            f,
            "{}",
            if self.contains(MmapProt::EXEC) {
                "x"
            } else {
                "-"
            }
        )?;
        Ok(())
    }
}

pub trait Mmap: Sized + Ord + Debug + Send {
    type Error: Debug;
    fn map(len: usize) -> Result<Self, Self::Error>;
    fn map_at(addr: GuestAddr, len: usize) -> Result<Self, Self::Error>;
    fn protect(addr: GuestAddr, len: usize, prot: MmapProt) -> Result<(), Self::Error>;
    fn huge_pages(addr: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn dont_dump(addr: GuestAddr, len: usize) -> Result<(), Self::Error>;
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
}
