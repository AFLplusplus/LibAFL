#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null};

    use libafl_asan::{expect_panic, hooks::strnlen::strnlen};

    #[test]
    fn test_strnlen_zero_length() {
        let ret = unsafe { strnlen(null() as *const c_char, 0) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strnlen_cs_null() {
        expect_panic();
        unsafe { strnlen(null() as *const c_char, 10) };
        unreachable!();
    }

    #[test]
    fn test_strnlen_cs_empty() {
        let data = c"";
        let ret = unsafe { strnlen(data.as_ptr() as *const c_char, 10) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strnlen_full() {
        let data = c"abcdefghij";
        let ret = unsafe { strnlen(data.as_ptr() as *const c_char, data.count_bytes()) };
        assert_eq!(ret, 10);
    }

    #[test]
    fn test_strnlen_partial() {
        let data = c"abcdefghij";
        let ret = unsafe { strnlen(data.as_ptr() as *const c_char, 5) };
        assert_eq!(ret, 5);
    }
}
