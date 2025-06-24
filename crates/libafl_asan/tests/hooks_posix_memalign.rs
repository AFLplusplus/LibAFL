#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ptr::null_mut, slice::from_raw_parts_mut};
    use std::os::raw::c_void;

    use libafl_asan::{expect_panic, hooks::posix_memalign::posix_memalign};

    #[test]
    fn posix_memalign_zero_size() {
        let mut memptr = null_mut();
        let ret = unsafe { posix_memalign(&mut memptr as *mut *mut c_void, 8, 0) };
        assert_eq!(ret, 0);
        assert_eq!(memptr, null_mut());
    }

    #[test]
    fn posix_memalign_size_not_multiple() {
        expect_panic();
        let mut memptr = null_mut();
        unsafe { posix_memalign(&mut memptr as *mut *mut c_void, 9, 8) };
        unreachable!();
    }

    #[test]
    fn posix_memalign_power_of_two() {
        let mut memptr = null_mut();
        let ret = unsafe { posix_memalign(&mut memptr as *mut *mut c_void, 8, 8) };
        assert_eq!(ret, 0);
        assert_ne!(memptr, null_mut());
        assert_eq!(memptr as usize & 7, 0);
    }

    #[test]
    fn posix_memalign_not_power_of_two() {
        expect_panic();
        let mut memptr = null_mut();
        unsafe { posix_memalign(&mut memptr as *mut *mut c_void, 7, 24) };
        unreachable!();
    }

    #[test]
    fn posix_memalign_buff() {
        let mut memptr = null_mut();
        let ret = unsafe { posix_memalign(&mut memptr as *mut *mut c_void, 32, 8) };
        assert_eq!(ret, 0);
        assert_ne!(memptr, null_mut());
        assert!(memptr as usize & 0x1f == 0);
        unsafe {
            from_raw_parts_mut(memptr as *mut u8, 8)
                .iter_mut()
                .for_each(|x| *x = 0)
        };
    }
}
