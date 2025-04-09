#[cfg(test)]
#[cfg(all(feature = "hooks"))]
mod tests {
    use core::{ffi::c_char, ptr::null_mut};

    use asan::{expect_panic, hooks::stpncpy::stpncpy};

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
        let dst = [0u8; 10];
        let ret = unsafe {
            stpncpy(
                dst.as_ptr() as *mut c_char,
                src.as_ptr() as *const c_char,
                dst.len(),
            )
        };
        assert_eq!(ret, unsafe { dst.as_ptr().add(dst.len()) as *mut c_char });
    }

    #[test]
    fn test_stpncpy_partial() {
        let mut vec = c"abcdefghijklmnopqrstuvwxyz".to_bytes().to_vec();
        let dst = vec.as_mut_slice();
        let src = c"uvwxyz".to_bytes();
        let ret = unsafe {
            stpncpy(
                dst.as_ptr() as *mut c_char,
                src.as_ptr() as *const c_char,
                dst.len(),
            )
        };
        assert_eq!(ret, unsafe { dst.as_ptr().add(dst.len()) as *mut c_char });
        let expected = c"uvwxyz".to_bytes();
        expected
            .iter()
            .zip(dst.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
        dst.iter().skip(src.len()).for_each(|x| assert_eq!(*x, 0));
    }
}
