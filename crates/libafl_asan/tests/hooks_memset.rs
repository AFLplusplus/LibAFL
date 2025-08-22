#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_void, ptr::null_mut};

    use libafl_asan::{expect_panic, hooks::memset::memset};

    #[test]
    fn test_memset_zero_length() {
        unsafe { memset(null_mut(), 0, 0) };
    }

    #[test]
    fn test_memset_null_s() {
        expect_panic();
        unsafe { memset(null_mut(), 0, 10) };
        unreachable!();
    }

    #[test]
    fn test_memset_zero_buffer() {
        let data = [0xffu8; 10];
        unsafe { memset(data.as_ptr() as *mut c_void, 0, data.len()) };
        data.iter().for_each(|x| assert_eq!(*x, 0));
    }

    #[test]
    fn test_memset_nonzero_buffer() {
        let data = [0u8; 10];
        unsafe { memset(data.as_ptr() as *mut c_void, 0xff, data.len()) };
        data.iter().for_each(|x| assert_eq!(*x, 0xff));
    }

    #[test]
    fn test_memset_partial_zero_buffer() {
        let data = [0xffu8; 10];
        unsafe { memset(data.as_ptr().add(2) as *mut c_void, 0x88, data.len() - 4) };
        data.iter()
            .skip(2)
            .take(6)
            .for_each(|x| assert_eq!(*x, 0x88));
        data.iter().take(2).for_each(|x| assert_eq!(*x, 0xff));
        data.iter().skip(8).for_each(|x| assert_eq!(*x, 0xff));
    }
}
