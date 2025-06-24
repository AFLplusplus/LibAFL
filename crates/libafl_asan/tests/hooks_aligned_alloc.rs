#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ptr::null_mut, slice::from_raw_parts_mut};

    use libafl_asan::{expect_panic, hooks::aligned_alloc::aligned_alloc};

    #[test]
    fn aligned_alloc_zero_size() {
        let ret = unsafe { aligned_alloc(8, 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn aligned_alloc_size_not_multiple() {
        expect_panic();
        unsafe { aligned_alloc(9, 8) };
        unreachable!();
    }

    #[test]
    fn aligned_alloc_power_of_two() {
        let addr = unsafe { aligned_alloc(8, 8) };
        assert_ne!(addr, null_mut());
        assert_eq!(addr as usize & 7, 0);
    }

    #[test]
    fn aligned_alloc_not_power_of_two() {
        expect_panic();
        unsafe { aligned_alloc(7, 24) };
        unreachable!();
    }

    #[test]
    fn aligned_alloc_buff() {
        let ret = unsafe { aligned_alloc(32, 8) };
        assert_ne!(ret, null_mut());
        assert!(ret as usize & 0x1f == 0);
        unsafe {
            from_raw_parts_mut(ret as *mut u8, 8)
                .iter_mut()
                .for_each(|x| *x = 0)
        };
    }
}
