#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::null_mut;

    use libafl_asan::{expect_panic, hooks::calloc::calloc, size_t};

    #[test]
    fn test_zero_length() {
        let ret = unsafe { calloc(0, 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_big_nobj() {
        let ret = unsafe { calloc(65536, 1) };
        assert_ne!(ret, null_mut());
    }

    #[test]
    fn test_big_size() {
        let ret = unsafe { calloc(1, 65536) };
        assert_ne!(ret, null_mut());
    }

    #[test]
    fn test_size_overflow() {
        expect_panic();
        unsafe { calloc(size_t::MAX, 10) };
        unreachable!();
    }
}
