#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ptr::null_mut, slice::from_raw_parts_mut};

    use libafl_asan::hooks::malloc::malloc;

    #[test]
    fn test_malloc_zero() {
        let p = unsafe { malloc(0) };
        assert_eq!(p, null_mut());
    }

    #[test]
    fn test_malloc_buff() {
        let p = unsafe { malloc(10) };
        assert_ne!(p, null_mut());
        unsafe {
            from_raw_parts_mut(p as *mut u8, 10)
                .iter_mut()
                .for_each(|x| *x = 0)
        };
    }
}
