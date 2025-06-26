#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null};

    use libafl_asan::{expect_panic, hooks::strcmp::strcmp};

    #[test]
    fn test_strcmp_null_s1() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strcmp(null(), data.as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    fn test_strcmp_null_s2() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strcmp(data.as_ptr() as *const c_char, null()) };
        unreachable!();
    }

    #[test]
    fn test_strcmp_eq() {
        let data = [1u8; 10];
        let ret = unsafe {
            strcmp(
                data.as_ptr() as *const c_char,
                data.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strcmp_zero_length_both() {
        let data = [0u8; 10];
        let ret = unsafe {
            strcmp(
                data.as_ptr() as *const c_char,
                data.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strcmp_zero_length_s1() {
        let data1 = [0u8; 10];
        let data2 = [1u8; 10];
        let ret = unsafe {
            strcmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_strcmp_zero_length_s2() {
        let data1 = [1u8; 10];
        let data2 = [0u8; 10];
        let ret = unsafe {
            strcmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_strcmp_eq_string() {
        let data1 = c"abcdefghij";
        let data2 = c"abcdefghij";
        let ret = unsafe {
            strcmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strcmp_s1_shorter() {
        let data1 = c"abcdefghi";
        let data2 = c"abcdefghij";
        let ret = unsafe {
            strcmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_strcmp_s1_longer() {
        let data1 = c"abcdefghij";
        let data2 = c"abcdefghi";
        let ret = unsafe {
            strcmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_strcmp_s1_less_than() {
        let data1 = c"abcdefghii";
        let data2 = c"abcdefghij";
        let ret = unsafe {
            strcmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_strcmp_s1_greater_than() {
        let data1 = c"abcdefghik";
        let data2 = c"abcdefghij";
        let ret = unsafe {
            strcmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_strcmp_case_not_ignored() {
        let data1 = c"abcdefghijklmnopqrstuvwxyz";
        let data2 = c"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let ret = unsafe {
            strcmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert!(ret > 0);
    }
}
