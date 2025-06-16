#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_void, ptr::null};

    use libafl_asan::{expect_panic, hooks::memcmp::memcmp};

    #[test]
    fn test_zero_length() {
        let ret = unsafe { memcmp(null(), null(), 0) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_null_cx() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { memcmp(null(), data.as_ptr() as *const c_void, data.len()) };
        unreachable!();
    }

    #[test]
    fn test_null_ct() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { memcmp(data.as_ptr() as *const c_void, null(), data.len()) };
        unreachable!();
    }

    #[test]
    fn test_eq() {
        let data = [0u8; 10];
        let ret = unsafe {
            memcmp(
                data.as_ptr() as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_lt() {
        let data1 = [0u8; 10];
        let data2 = [1u8; 10];
        let ret = unsafe {
            memcmp(
                data1.as_ptr() as *const c_void,
                data2.as_ptr() as *const c_void,
                data1.len(),
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_gt() {
        let data1 = [1u8; 10];
        let data2 = [0u8; 10];
        let ret = unsafe {
            memcmp(
                data1.as_ptr() as *const c_void,
                data2.as_ptr() as *const c_void,
                data1.len(),
            )
        };
        assert!(ret > 0);
    }
}
