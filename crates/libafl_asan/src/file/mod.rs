use alloc::fmt::Debug;
use core::ffi::CStr;

#[cfg(feature = "libc")]
pub mod libc;

#[cfg(all(feature = "linux", target_os = "linux"))]
pub mod linux;

pub trait FileReader: Debug + Send + Sized {
    type Error: Debug;
    fn new(path: &'static CStr) -> Result<Self, Self::Error>;
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}
