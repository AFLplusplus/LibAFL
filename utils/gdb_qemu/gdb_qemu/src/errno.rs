use libc::__errno_location;

pub fn errno() -> i32 {
    unsafe { *__errno_location() }
}
