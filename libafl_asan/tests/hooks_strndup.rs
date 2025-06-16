#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_char,
        ptr::{null, null_mut},
        slice::from_raw_parts,
    };

    use libafl_asan::{expect_panic, hooks::strndup::strndup};

    #[test]
    fn test_strndup_cs_null_zero_length() {
        let ret = unsafe { strndup(null() as *const c_char, 0x0) };
        assert_ne!(ret, null_mut());
        assert_eq!(unsafe { *ret }, 0);
    }

    #[test]
    fn test_strndup_cs_null() {
        expect_panic();
        unsafe { strndup(null() as *const c_char, 0x10) };
        unreachable!();
    }

    #[test]
    fn test_strndup_cs_empty() {
        let data = c"";
        let ret = unsafe { strndup(data.as_ptr() as *const c_char, 0x0) };
        assert_ne!(ret, null_mut());
        assert_eq!(unsafe { *ret }, 0);
    }

    #[test]
    fn test_strndup_full() {
        let data = c"abcdefghij";
        let ret = unsafe { strndup(data.as_ptr() as *const c_char, data.count_bytes()) };
        assert_ne!(ret, null_mut());
        data.to_bytes()
            .iter()
            .zip(unsafe { from_raw_parts(ret as *const u8, data.count_bytes()) })
            .for_each(|(x, y)| assert_eq!(x, y));
    }

    #[test]
    fn test_strndup_partial() {
        let data = c"abcdefghij";
        let ret = unsafe { strndup(data.as_ptr() as *const c_char, 4) };
        assert_ne!(ret, null_mut());
        let expected = c"abcd";
        expected
            .to_bytes()
            .iter()
            .zip(unsafe { from_raw_parts(ret as *const u8, expected.count_bytes()) })
            .for_each(|(x, y)| assert_eq!(x, y));
    }
}
