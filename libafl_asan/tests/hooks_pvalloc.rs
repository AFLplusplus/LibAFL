#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ptr::null_mut, slice::from_raw_parts_mut};

    use libafl_asan::hooks::pvalloc::pvalloc;

    #[test]
    fn test_pvalloc_zero() {
        let p = unsafe { pvalloc(0) };
        assert_ne!(p, null_mut());
        assert!(p as usize & 0xfff == 0);
        unsafe {
            from_raw_parts_mut(p as *mut u8, 4096)
                .iter_mut()
                .for_each(|x| *x = 0)
        };
    }

    #[test]
    fn test_pvalloc_buff() {
        let p = unsafe { pvalloc(4097) };
        assert_ne!(p, null_mut());
        assert!(p as usize & 0xfff == 0);
        unsafe {
            from_raw_parts_mut(p as *mut u8, 8192)
                .iter_mut()
                .for_each(|x| *x = 0)
        };
    }
}
