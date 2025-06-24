#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null_mut};

    use libafl_asan::{expect_panic, hooks::stpcpy::stpcpy};

    #[test]
    fn test_stpcpy_dst_null() {
        let src = [0u8; 10];
        expect_panic();
        unsafe { stpcpy(null_mut(), src.as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    fn test_stpcpy_src_null() {
        let dst = [0u8; 10];
        expect_panic();
        unsafe { stpcpy(dst.as_ptr() as *mut c_char, null_mut()) };
        unreachable!();
    }

    #[test]
    fn test_stpcpy_full() {
        let src = [0xffu8; 10];
        let dst = [0u8; 10];
        let ret = unsafe { stpcpy(dst.as_ptr() as *mut c_char, src.as_ptr() as *const c_char) };
        assert_eq!(ret, unsafe { dst.as_ptr().add(src.len()) as *mut c_char });
    }

    #[test]
    fn test_stpcpy_partial() {
        let mut vec = c"abcdefghijklmnopqrstuvwxyz".to_bytes().to_vec();
        let dst = vec.as_mut_slice();
        let src = c"uvwxyz".to_bytes();
        let ret = unsafe {
            stpcpy(
                dst.as_ptr().add(2) as *mut c_char,
                src.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, unsafe {
            dst.as_ptr().add(2).add(src.len()) as *mut c_char
        });
        let expected = c"abuvwxyz".to_bytes();
        expected
            .iter()
            .zip(dst.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
        let remaining = c"jklmnopqrstuvwxyz".to_bytes();
        remaining
            .iter()
            .zip(dst.iter().skip(2).skip(src.len()).skip(1))
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }
}
