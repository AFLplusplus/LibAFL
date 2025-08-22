#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_void, ptr::null_mut};

    use libafl_asan::{expect_panic, hooks::bzero::bzero};

    #[test]
    fn test_bzero_zero_length() {
        unsafe { bzero(null_mut(), 0) };
    }

    #[test]
    fn test_bzero_null_s() {
        expect_panic();
        unsafe { bzero(null_mut(), 10) };
        unreachable!();
    }

    #[test]
    fn test_bzero_zero_buffer() {
        let data = [0xffu8; 10];
        unsafe { bzero(data.as_ptr() as *mut c_void, data.len()) };
        data.iter().for_each(|x| assert_eq!(*x, 0));
    }

    #[test]
    fn test_bzero_partial_zero_buffer() {
        let data = [0xffu8; 10];
        unsafe { bzero(data.as_ptr().add(2) as *mut c_void, data.len() - 4) };
        data.iter().skip(2).take(6).for_each(|x| assert_eq!(*x, 0));
        data.iter().take(2).for_each(|x| assert_eq!(*x, 0xff));
        data.iter().skip(8).for_each(|x| assert_eq!(*x, 0xff));
    }
}
