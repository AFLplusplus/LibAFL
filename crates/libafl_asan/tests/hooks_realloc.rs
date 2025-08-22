#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ptr::null_mut, slice::from_raw_parts_mut};

    use libafl_asan::hooks::realloc::realloc;

    #[test]
    fn test_realloc_p_null_size_zero() {
        let p = unsafe { realloc(null_mut(), 0) };
        assert_eq!(p, null_mut());
    }

    #[test]
    fn test_realloc_p_null() {
        let p = unsafe { realloc(null_mut(), 10) };
        assert_ne!(p, null_mut());
        unsafe {
            from_raw_parts_mut(p as *mut u8, 10)
                .iter_mut()
                .for_each(|x| *x = 0)
        };
    }

    #[test]
    fn test_realloc_size_zero() {
        let p = unsafe { realloc(null_mut(), 10) };
        assert_ne!(p, null_mut());
        let q = unsafe { realloc(p, 0) };
        assert_eq!(q, null_mut());
    }

    #[test]
    fn test_realloc_enlarge() {
        let p = unsafe { realloc(null_mut(), 10) };
        assert_ne!(p, null_mut());
        unsafe {
            from_raw_parts_mut(p as *mut u8, 10)
                .iter_mut()
                .for_each(|x| *x = 0x88)
        };
        let q = unsafe { realloc(p, 20) };
        assert_ne!(q, null_mut());

        unsafe {
            from_raw_parts_mut(q as *mut u8, 10)
                .iter()
                .for_each(|x| assert_eq!(*x, 0x88));
        };
    }

    #[test]
    fn test_realloc_shrink() {
        let p = unsafe { realloc(null_mut(), 20) };
        assert_ne!(p, null_mut());
        unsafe {
            from_raw_parts_mut(p as *mut u8, 20)
                .iter_mut()
                .for_each(|x| *x = 0x88)
        };
        let q = unsafe { realloc(p, 10) };
        assert_ne!(q, null_mut());

        unsafe {
            from_raw_parts_mut(q as *mut u8, 10)
                .iter()
                .for_each(|x| assert_eq!(*x, 0x88));
        };
    }
}
