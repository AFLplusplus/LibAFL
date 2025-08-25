#[cfg(target_os = "linux")]
use libc::__errno_location;

#[cfg(target_vendor= "apple")]
use libc::__error;

#[cfg(target_os = "linux")]
pub fn errno() -> i32 {
    unsafe { *__errno_location() }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub fn errno() -> i32 {
    unsafe { *__error() }
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub fn errno() -> i32 {
    // TODO: Add support for more platforms.
    0
}