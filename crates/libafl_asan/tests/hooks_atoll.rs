#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null_mut};
    use std::ffi::c_longlong;

    use libafl_asan::{expect_panic, hooks::atoll::atoll};

    #[test]
    fn atoll_test_null() {
        expect_panic();
        unsafe { atoll(null_mut()) };
        unreachable!();
    }

    #[test]
    fn atoll_test_number() {
        let ret = unsafe { atoll(c"123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoll_test_zero() {
        let ret = unsafe { atoll(c"0".as_ptr() as *const c_char) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn atoll_test_negative_zero() {
        let ret = unsafe { atoll(c"-0".as_ptr() as *const c_char) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn atoll_test_leading_whitespace_1() {
        let ret = unsafe { atoll(c"   123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoll_test_leading_whitespace_2() {
        let ret = unsafe { atoll(c"\n\n123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoll_test_leading_whitespace_3() {
        let ret = unsafe { atoll(c"\r\r123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoll_test_leading_whitespace_4() {
        let ret = unsafe { atoll(c"\t\t123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoll_test_leading_whitespace_negative() {
        let ret = unsafe { atoll(c"   -123".as_ptr() as *const c_char) };
        assert_eq!(ret, -123);
    }

    #[test]
    fn atoll_test_leading_zeroes() {
        let ret = unsafe { atoll(c"000123".as_ptr() as *const c_char) };
        assert_eq!(ret, 123);
    }

    #[test]
    fn atoll_test_negative() {
        let ret = unsafe { atoll(c"-123".as_ptr() as *const c_char) };
        assert_eq!(ret, -123);
    }

    #[test]
    fn atoll_test_non_numeric() {
        let ret = unsafe { atoll(c"12a3".as_ptr() as *const c_char) };
        assert_eq!(ret, 12);
    }

    #[test]
    fn atoll_test_non_numeric_negative() {
        let ret = unsafe { atoll(c"-12a3".as_ptr() as *const c_char) };
        assert_eq!(ret, -12);
    }

    #[test]
    fn atoll_test_max() {
        let ret = unsafe { atoll(c"9223372036854775807".as_ptr() as *const c_char) };
        assert_eq!(ret, c_longlong::MAX);
    }

    #[test]
    fn atoll_test_min() {
        let ret = unsafe { atoll(c"-9223372036854775808".as_ptr() as *const c_char) };
        assert_eq!(ret, c_longlong::MIN);
    }

    #[test]
    fn atoll_test_overflow() {
        expect_panic();
        unsafe { atoll(c"9223372036854775808".as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    fn atoll_test_underflow() {
        expect_panic();
        unsafe { atoll(c"-9223372036854775809".as_ptr() as *const c_char) };
        unreachable!();
    }
}
