#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ptr::null_mut, slice::from_raw_parts_mut};

    use libafl_asan::{expect_panic, hooks::memalign::memalign};

    #[test]
    fn memalign_zero_size() {
        let ret = unsafe { memalign(8, 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn memalign_size_not_multiple() {
        expect_panic();
        unsafe { memalign(9, 8) };
        unreachable!();
    }

    #[test]
    fn memalign_power_of_two() {
        let addr = unsafe { memalign(8, 8) };
        assert_ne!(addr, std::ptr::null_mut());
        assert_eq!(addr as usize & 7, 0);
    }

    #[test]
    fn memalign_not_power_of_two() {
        expect_panic();
        unsafe { memalign(7, 24) };
        unreachable!();
    }

    #[test]
    fn memalign_buff() {
        let ret = unsafe { memalign(32, 8) };
        assert_ne!(ret, null_mut());
        assert!(ret as usize & 0x1f == 0);
        unsafe {
            from_raw_parts_mut(ret as *mut u8, 8)
                .iter_mut()
                .for_each(|x| *x = 0)
        };
    }
}
