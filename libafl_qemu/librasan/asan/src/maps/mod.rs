use core::fmt::Debug;

mod decode;
pub mod entry;

pub mod iterator;

#[cfg(feature = "libc")]
pub mod libc;

#[cfg(feature = "linux")]
pub mod linux;

pub trait MapReader: Sized {
    type Error: Debug;
    fn new() -> Result<Self, Self::Error>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}
