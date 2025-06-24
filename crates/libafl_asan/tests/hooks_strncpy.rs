#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_char,
        ptr::{null, null_mut},
        slice::from_raw_parts,
    };

    use libafl_asan::{expect_panic, hooks::strncpy::strncpy};

    #[test]
    fn test_strncpy_zero_length() {
        let ret = unsafe { strncpy(null_mut(), null(), 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_strncpy_null_dest() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strncpy(null_mut(), data.as_ptr() as *const c_char, data.len()) };
        unreachable!();
    }

    #[test]
    fn test_strncpy_null_src() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strncpy(data.as_ptr() as *mut c_char, null(), data.len()) };
        unreachable!();
    }

    #[test]
    fn test_strncpy_full() {
        let mut vec = "abcde\0zzzzzzzzzzzzzzz".as_bytes().to_vec();
        let dest = vec.as_mut_slice();
        let src = c"fghij";
        let ret = unsafe {
            strncpy(
                dest.as_ptr() as *mut c_char,
                src.as_ptr() as *const c_char,
                5,
            )
        };
        assert_eq!(ret, dest.as_ptr() as *mut c_char);
        let expected = "fghij\0zzzzzzzzzzzzzzz";
        expected
            .as_bytes()
            .iter()
            .zip(unsafe { from_raw_parts(dest.as_ptr(), dest.len()) })
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }

    #[test]
    fn test_strncpy_partial() {
        let mut vec = "abcde\0zzzzzzzzzzzzzzz".as_bytes().to_vec();
        let dest = vec.as_mut_slice();
        let src = c"fghij";
        let ret = unsafe {
            strncpy(
                dest.as_ptr() as *mut c_char,
                src.as_ptr() as *const c_char,
                3,
            )
        };
        assert_eq!(ret, dest.as_ptr() as *mut c_char);
        let expected = "fghde\0zzzzzzzzzzzzzzz";
        expected
            .as_bytes()
            .iter()
            .zip(unsafe { from_raw_parts(dest.as_ptr(), dest.len()) })
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }
}
