#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null_mut};
    use std::ffi::c_int;

    use libafl_asan::{expect_panic, hooks::atoi::atoi};

    #[test]
    fn atoi_test_null() {
        expect_panic();
        unsafe { atoi(null_mut()) };
        unreachable!();
    }

    #[test]
    fn atoi_test_number() {
        let ret = unsafe { atoi(c"123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoi_test_zero() {
        let ret = unsafe { atoi(c"0".as_ptr() as *const c_char) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn atoi_test_negative_zero() {
        let ret = unsafe { atoi(c"-0".as_ptr() as *const c_char) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn atoi_test_leading_whitespace_1() {
        let ret = unsafe { atoi(c"   123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoi_test_leading_whitespace_2() {
        let ret = unsafe { atoi(c"\n\n123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoi_test_leading_whitespace_3() {
        let ret = unsafe { atoi(c"\r\r123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoi_test_leading_whitespace_4() {
        let ret = unsafe { atoi(c"\t\t123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoi_test_leading_whitespace_negative() {
        let ret = unsafe { atoi(c"   -123".as_ptr() as *const c_char) };
        assert_eq!(ret, -123);
    }

    #[test]
    fn atoi_test_leading_zeroes() {
        let ret = unsafe { atoi(c"000123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoi_test_negative() {
        let ret = unsafe { atoi(c"-123".as_ptr() as *const c_char) };
        assert_eq!(ret, -123);
    }

    #[test]
    fn atoi_test_non_numeric() {
        let ret = unsafe { atoi(c"12a3".as_ptr() as *const c_char) };
        assert_eq!(ret, 12);
    }

    #[test]
    fn atoi_test_non_numeric_negative() {
        let ret = unsafe { atoi(c"-12a3".as_ptr() as *const c_char) };
        assert_eq!(ret, -12);
    }

    #[test]
    fn atoi_test_max() {
        let ret = unsafe { atoi(c"2147483647".as_ptr() as *const c_char) };
        assert_eq!(ret, c_int::MAX);
    }

    #[test]
    fn atoi_test_min() {
        let ret = unsafe { atoi(c"-2147483648".as_ptr() as *const c_char) };
        assert_eq!(ret, c_int::MIN);
    }

    #[test]
    fn atoi_test_overflow() {
        expect_panic();
        unsafe { atoi(c"2147483648".as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    fn atoi_test_underflow() {
        expect_panic();
        unsafe { atoi(c"-2147483649".as_ptr() as *const c_char) };
        unreachable!();
    }
}
