#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_char,
        ptr::{null, null_mut},
    };

    use libafl_asan::{expect_panic, hooks::strncat::strncat};

    #[test]
    fn test_strncat_bounds() {
        use libafl_asan::{asan_alloc, asan_dealloc};

        unsafe {
            let s = asan_alloc(6, 8) as *mut u8;
            core::slice::from_raw_parts_mut(s, 6).copy_from_slice(b"ab\0zzz");
            let ct = asan_alloc(3, 8) as *mut u8;
            core::slice::from_raw_parts_mut(ct, 3).copy_from_slice(b"cde");
            assert_eq!(
                strncat(s as *mut c_char, ct as *const c_char, 3),
                s as *mut c_char
            );
            assert_eq!(core::slice::from_raw_parts(s, 6), b"abcde\0");
            asan_dealloc(ct.cast());
            asan_dealloc(s.cast());
        }
    }

    #[test]
    fn test_strncat_zero_length() {
        let ret = unsafe { strncat(null_mut(), null_mut(), 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_strncat_null_s() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strncat(null_mut(), data.as_ptr() as *const c_char, data.len()) };
        unreachable!();
    }

    #[test]
    fn test_strncat_null_s2() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strncat(data.as_ptr() as *mut c_char, null(), 10) };
        unreachable!();
    }

    #[test]
    fn test_strncat_zero_length_both() {
        let data = [0u8; 10];
        let ret = unsafe {
            strncat(
                data.as_ptr() as *mut c_char,
                data.as_ptr() as *const c_char,
                data.len(),
            )
        };
        assert_eq!(ret, data.as_ptr() as *mut c_char);
    }

    #[test]
    fn test_strncat_appends() {
        let mut vec = "abcde\0zzzzzzzzzzzzzzz".as_bytes().to_vec();
        let s = vec.as_mut_slice();
        let ct = c"fghij";
        let ret = unsafe {
            strncat(
                s.as_ptr() as *mut c_char,
                ct.as_ptr() as *const c_char,
                ct.count_bytes(),
            )
        };
        assert_eq!(ret, s.as_ptr() as *mut c_char);
        let expected = c"abcdefghij";
        expected
            .to_bytes()
            .iter()
            .zip(s.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }

    #[test]
    fn test_strncat_appends_partial() {
        let mut vec = "abcde\0zzzzzzzzzzzzzzz".as_bytes().to_vec();
        let s = vec.as_mut_slice();
        let ct = c"fghij";
        let ret = unsafe { strncat(s.as_ptr() as *mut c_char, ct.as_ptr() as *const c_char, 3) };
        assert_eq!(ret, s.as_ptr() as *mut c_char);
        let expected = c"abcdefgh";
        expected
            .to_bytes()
            .iter()
            .zip(s.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }
}
