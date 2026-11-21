#[cfg(all(test, feature = "hooks", feature = "syscalls", target_os = "linux"))]
mod tests {
    use core::{ffi::c_void, ptr::null_mut};

    use libafl_asan::{asan_alloc, asan_dealloc, expect_panic, hooks::write::linux::write, size_t};

    #[test]
    fn test_linux_pipe_write() {
        use std::{io::Read, os::fd::AsRawFd};

        let (mut reader, writer) = std::io::pipe().unwrap();
        let mut out = [0u8; 4];
        unsafe {
            let src = asan_alloc(4, 8) as *mut u8;
            core::slice::from_raw_parts_mut(src, 4).copy_from_slice(b"pong");
            assert_eq!(write(writer.as_raw_fd(), src.cast(), 4), 4);
            reader.read_exact(&mut out).unwrap();
            assert_eq!(&out, b"pong");
            assert_eq!(write(writer.as_raw_fd(), src.add(4).cast(), 0), 0);
            assert_eq!(write(-1, null_mut(), 0), -1);
            assert_eq!(write(-1, src.cast(), 4), -1);
            asan_dealloc(src.cast());
        }
    }

    #[test]
    fn test_read_invalid_args() {
        let fd = 0;
        let buf = null_mut();
        let count = 10;

        expect_panic();

        unsafe { write(fd, buf, count) };
        unreachable!();
    }

    #[test]
    fn test_read_valid_args() {
        let fd = -1;
        let buf = null_mut();
        let count = 0;

        let ret = unsafe { write(fd, buf, count) };
        assert!(ret < 0);
    }

    #[test]
    fn test_read_valid_args_with_buffer() {
        let fd = -1;
        let mut buf = [0u8; 10];
        let count = buf.len() as size_t;

        let ret = unsafe { write(fd, buf.as_mut_ptr() as *mut c_void, count) };
        assert!(ret < 0);
    }
}
