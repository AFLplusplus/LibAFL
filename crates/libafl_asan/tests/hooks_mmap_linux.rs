#[cfg(all(test, feature = "hooks", feature = "syscalls", target_os = "linux"))]
mod tests {
    use core::{ffi::c_void, ptr::null_mut};

    use libafl_asan::{
        GuestAddr, asan_load, asan_page_size, asan_store,
        hooks::{mmap::linux::mmap, munmap::linux::munmap},
    };

    const MAP_FAILED: *mut c_void = GuestAddr::MAX as *mut c_void;

    #[test]
    fn test_linux_mmap_and_munmap() {
        unsafe {
            let page = asan_page_size();
            let prot = libc::PROT_READ | libc::PROT_WRITE;

            let anon = mmap(
                null_mut(),
                page,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(anon, MAP_FAILED);
            asan_store(anon, page);
            *anon.cast::<u8>() = 0x5a;
            asan_load(anon, page);
            assert_eq!(munmap(anon, page), 0);

            assert_eq!(
                mmap(null_mut(), page, prot, libc::MAP_PRIVATE, -1, 0),
                MAP_FAILED
            );
            assert_eq!(
                mmap(
                    null_mut(),
                    page,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    1
                ),
                MAP_FAILED
            );

            let fd = libc::memfd_create(c"asan_mmap".as_ptr(), 0);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, page as libc::off_t), 0);
            assert_eq!(
                mmap(null_mut(), page, prot, libc::MAP_SHARED, fd, -4096),
                MAP_FAILED
            );
            assert_eq!(
                mmap(null_mut(), page, prot, libc::MAP_SHARED, fd, 1),
                MAP_FAILED
            );
            let file_map = mmap(null_mut(), page, prot, libc::MAP_SHARED, fd, 0);
            assert_ne!(file_map, MAP_FAILED);
            asan_store(file_map, page);
            assert_eq!(munmap(file_map, page), 0);
            assert_eq!(libc::close(fd), 0);
        }
    }
}
