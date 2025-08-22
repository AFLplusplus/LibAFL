//! # die
//! This module supports exiting the process
#[cfg(feature = "libc")]
pub use crate::exit::libc::abort;
#[cfg(feature = "libc")]
pub use crate::exit::libc::exit;
#[cfg(all(feature = "linux", target_os = "linux", not(feature = "libc")))]
pub use crate::exit::linux::abort;
#[cfg(all(feature = "linux", target_os = "linux", not(feature = "libc")))]
pub use crate::exit::linux::exit;

#[cfg(feature = "libc")]
pub mod libc;

#[cfg(all(feature = "linux", target_os = "linux"))]
pub mod linux;

#[cfg(all(
    not(feature = "libc"),
    not(all(feature = "linux", target_os = "linux"))
))]
pub fn abort() -> ! {
    loop {}
}

#[cfg(all(
    not(feature = "libc"),
    not(all(feature = "linux", target_os = "linux"))
))]
pub fn exit(_status: core::ffi::c_int) -> ! {
    loop {}
}
