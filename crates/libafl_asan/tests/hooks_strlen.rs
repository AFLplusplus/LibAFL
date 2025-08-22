#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null};

    use libafl_asan::{expect_panic, hooks::strlen::strlen};

    #[test]
    fn test_strlen_cs_null() {
        expect_panic();
        unsafe { strlen(null() as *const c_char) };
        unreachable!();
    }

    #[test]
    fn test_strlen_cs_empty() {
        let data = c"";
        let ret = unsafe { strlen(data.as_ptr() as *const c_char) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strlen_full() {
        let data = c"abcdefghij";
        let ret = unsafe { strlen(data.as_ptr() as *const c_char) };
        assert_eq!(ret, 10);
    }
}
