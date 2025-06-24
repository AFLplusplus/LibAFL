#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ptr::null_mut, slice::from_raw_parts_mut};

    use libafl_asan::{expect_panic, hooks::reallocarray::reallocarray, size_t};

    #[test]
    fn test_reallocarray_p_null_size_zero() {
        let p = unsafe { reallocarray(null_mut(), 0, 0) };
        assert_eq!(p, null_mut());
    }

    #[test]
    fn test_reallocarray_p_null() {
        let p = unsafe { reallocarray(null_mut(), 10, 10) };
        assert_ne!(p, null_mut());
        unsafe {
            from_raw_parts_mut(p as *mut u8, 10)
                .iter_mut()
                .for_each(|x| *x = 0)
        };
    }

    #[test]
    fn test_reallocarray_size_zero() {
        let p = unsafe { reallocarray(null_mut(), 10, 10) };
        assert_ne!(p, null_mut());
        let q = unsafe { reallocarray(p, 0, 0) };
        assert_eq!(q, null_mut());
    }

    #[test]
    fn test_reallocarray_size_overflow() {
        expect_panic();
        unsafe { reallocarray(null_mut(), size_t::MAX, size_t::MAX) };
        unreachable!();
    }

    #[test]
    fn test_reallocarray_enlarge() {
        let p = unsafe { reallocarray(null_mut(), 10, 1) };
        assert_ne!(p, null_mut());
        unsafe {
            from_raw_parts_mut(p as *mut u8, 10)
                .iter_mut()
                .for_each(|x| *x = 0x88)
        };
        let q = unsafe { reallocarray(p, 20, 1) };
        assert_ne!(q, null_mut());

        unsafe {
            from_raw_parts_mut(q as *mut u8, 10)
                .iter()
                .for_each(|x| assert_eq!(*x, 0x88));
        };
    }

    #[test]
    fn test_reallocarray_shrink() {
        let p = unsafe { reallocarray(null_mut(), 20, 1) };
        assert_ne!(p, null_mut());
        unsafe {
            from_raw_parts_mut(p as *mut u8, 20)
                .iter_mut()
                .for_each(|x| *x = 0x88)
        };
        let q = unsafe { reallocarray(p, 10, 1) };
        assert_ne!(q, null_mut());

        unsafe {
            from_raw_parts_mut(q as *mut u8, 10)
                .iter()
                .for_each(|x| assert_eq!(*x, 0x88));
        };
    }
}
