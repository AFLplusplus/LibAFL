#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null_mut};

    use libafl_asan::{expect_panic, hooks::stpncpy::stpncpy};

    #[test]
    fn test_stpncpy_bounds() {
        use libafl_asan::{asan_alloc, asan_dealloc};

        unsafe {
            let src = asan_alloc(4, 8) as *mut u8;
            let dst = asan_alloc(6, 8) as *mut u8;
            core::slice::from_raw_parts_mut(src, 4).copy_from_slice(b"abcd");
            assert_eq!(
                stpncpy(dst as *mut c_char, src as *const c_char, 4),
                dst.add(4) as *mut c_char
            );
            assert_eq!(
                stpncpy(dst as *mut c_char, c"xy".as_ptr(), 6),
                dst.add(2) as *mut c_char
            );
            assert_eq!(core::slice::from_raw_parts(dst, 6), b"xy\0\0\0\0");
            asan_dealloc(dst.cast());
            asan_dealloc(src.cast());
        }
    }

    #[test]
    fn test_stpncpy_zero_length() {
        let ret = unsafe { stpncpy(null_mut(), null_mut(), 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_stpncpy_dst_null() {
        let src = [0u8; 10];
        expect_panic();
        unsafe { stpncpy(null_mut(), src.as_ptr() as *const c_char, 10) };
        unreachable!();
    }

    #[test]
    fn test_stpncpy_src_null() {
        let dst = [0u8; 10];
        expect_panic();
        unsafe { stpncpy(dst.as_ptr() as *mut c_char, null_mut(), dst.len()) };
        unreachable!();
    }

    #[test]
    fn test_stpncpy_full() {
        let src = [0xffu8; 10];
        let mut dst = [0u8; 10];
        let ret = unsafe {
            stpncpy(
                dst.as_mut_ptr() as *mut c_char,
                src.as_ptr() as *const c_char,
                dst.len(),
            )
        };
        assert_eq!(ret, unsafe {
            dst.as_mut_ptr().add(dst.len()) as *mut c_char
        });
    }

    #[test]
    fn test_stpncpy_partial() {
        let mut vec = c"abcdefghijklmnopqrstuvwxyz".to_bytes().to_vec();
        let dst = vec.as_mut_slice();
        let src = c"uvwxyz";
        let ret = unsafe { stpncpy(dst.as_mut_ptr() as *mut c_char, src.as_ptr(), dst.len()) };
        assert_eq!(ret, unsafe {
            dst.as_mut_ptr().add(src.count_bytes()) as *mut c_char
        });
        let expected = c"uvwxyz".to_bytes();
        expected
            .iter()
            .zip(dst.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
        dst.iter()
            .skip(src.count_bytes())
            .for_each(|x| assert_eq!(*x, 0));
    }
}
