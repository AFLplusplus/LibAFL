#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_char,
        ptr::{null, null_mut},
    };

    use asan::{expect_panic, hooks::strncat::strncat};

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
