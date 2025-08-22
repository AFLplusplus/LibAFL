#[cfg(all(
    test,
    feature = "hooks",
    feature = "linux",
    target_os = "linux",
    not(feature = "libc")
))]
mod tests {
    use core::{ffi::c_void, ptr::null_mut};

    use libafl_asan::hooks::{expect_panic, read::linux::read, size_t};

    #[test]
    fn test_read_invalid_args() {
        let fd = 0;
        let buf = null_mut();
        let count = 10;

        expect_panic();

        unsafe { read(fd, buf, count) };
        unreachable!();
    }

    #[test]
    fn test_read_valid_args() {
        let fd = -1;
        let buf = null_mut();
        let count = 0;

        let ret = unsafe { read(fd, buf, count) };
        assert!(ret < 0);
    }

    #[test]
    fn test_read_valid_args_with_buffer() {
        let fd = -1;
        let mut buf = [0u8; 10];
        let count = buf.len() as size_t;

        let ret = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, count) };
        assert!(ret < 0);
    }
}
