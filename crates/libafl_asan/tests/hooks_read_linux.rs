#[cfg(all(test, feature = "hooks", feature = "syscalls", target_os = "linux"))]
mod tests {
    use core::{ffi::c_void, ptr::null_mut};

    use libafl_asan::{asan_alloc, asan_dealloc, expect_panic, hooks::read::linux::read, size_t};

    #[test]
    fn test_linux_pipe_read() {
        use std::{io::Write, os::fd::AsRawFd};

        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"ping").unwrap();
        unsafe {
            let dst = asan_alloc(4, 8) as *mut u8;
            assert_eq!(read(reader.as_raw_fd(), dst.cast(), 4), 4);
            assert_eq!(core::slice::from_raw_parts(dst, 4), b"ping");
            assert_eq!(read(reader.as_raw_fd(), dst.add(4).cast(), 0), 0);
            assert_eq!(read(-1, null_mut(), 0), -1);
            assert_eq!(read(-1, dst.cast(), 4), -1);
            asan_dealloc(dst.cast());
        }
    }

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
