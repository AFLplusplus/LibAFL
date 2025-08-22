#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_char,
        ptr::{null, null_mut},
    };

    use libafl_asan::{expect_panic, hooks::strcpy::strcpy};

    #[test]
    fn test_strcpy_null_s() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strcpy(null_mut(), data.as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    fn test_strcpy_null_s2() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strcpy(data.as_ptr() as *mut c_char, null()) };
        unreachable!();
    }

    #[test]
    fn test_strcpy_zero_length_both() {
        let data = [0u8; 10];
        let ret = unsafe { strcpy(data.as_ptr() as *mut c_char, data.as_ptr() as *const c_char) };
        assert_eq!(ret, data.as_ptr() as *mut c_char);
    }

    #[test]
    fn test_strcpy_copies() {
        let mut vec = c"abcdefghij".to_bytes().to_vec();
        let s = vec.as_mut_slice();
        let ct = c"klmnop";
        let ret = unsafe { strcpy(s.as_ptr() as *mut c_char, ct.as_ptr() as *const c_char) };
        assert_eq!(ret, s.as_ptr() as *mut c_char);
        ct.to_bytes()
            .iter()
            .zip(s.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }
}
