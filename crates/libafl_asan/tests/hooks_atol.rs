#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null_mut};
    use std::ffi::c_long;

    use libafl_asan::{expect_panic, hooks::atol::atol};

    #[test]
    fn atol_test_null() {
        expect_panic();
        unsafe { atol(null_mut()) };
        unreachable!();
    }

    #[test]
    fn atol_test_number() {
        let ret = unsafe { atol(c"123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atol_test_zero() {
        let ret = unsafe { atol(c"0".as_ptr() as *const c_char) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn atol_test_negative_zero() {
        let ret = unsafe { atol(c"-0".as_ptr() as *const c_char) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn atol_test_leading_whitespace_1() {
        let ret = unsafe { atol(c"   123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atol_test_leading_whitespace_2() {
        let ret = unsafe { atol(c"\n\n123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atol_test_leading_whitespace_3() {
        let ret = unsafe { atol(c"\r\r123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atol_test_leading_whitespace_4() {
        let ret = unsafe { atol(c"\t\t123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atol_test_leading_whitespace_negative() {
        let ret = unsafe { atol(c"   -123".as_ptr() as *const c_char) };
        assert_eq!(ret, -123);
    }

    #[test]
    fn atol_test_leading_zeroes() {
        let ret = unsafe { atol(c"000123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atol_test_negative() {
        let ret = unsafe { atol(c"-123".as_ptr() as *const c_char) };
        assert_eq!(ret, -123);
    }

    #[test]
    fn atol_test_non_numeric() {
        let ret = unsafe { atol(c"12a3".as_ptr() as *const c_char) };
        assert_eq!(ret, 12);
    }

    #[test]
    fn atol_test_non_numeric_negative() {
        let ret = unsafe { atol(c"-12a3".as_ptr() as *const c_char) };
        assert_eq!(ret, -12);
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn atol_test_max() {
        let ret = unsafe { atol(c"2147483647".as_ptr() as *const c_char) };
        assert_eq!(ret, c_long::MAX);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn atol_test_max() {
        let ret = unsafe { atol(c"9223372036854775807".as_ptr() as *const c_char) };
        assert_eq!(ret, c_long::MAX);
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn atol_test_min() {
        let ret = unsafe { atol(c"-2147483648".as_ptr() as *const c_char) };
        assert_eq!(ret, c_long::MIN);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn atol_test_min() {
        let ret = unsafe { atol(c"-9223372036854775808".as_ptr() as *const c_char) };
        assert_eq!(ret, c_long::MIN);
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn atol_test_overflow() {
        expect_panic();
        unsafe { atol(c"2147483648".as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn atol_test_overflow() {
        expect_panic();
        unsafe { atol(c"9223372036854775808".as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn atol_test_underflow() {
        expect_panic();
        unsafe { atol(c"-2147483649".as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn atol_test_underflow() {
        expect_panic();
        unsafe { atol(c"-9223372036854775809".as_ptr() as *const c_char) };
        unreachable!();
    }
}
