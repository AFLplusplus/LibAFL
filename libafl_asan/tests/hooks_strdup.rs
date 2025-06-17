#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_char,
        ptr::{null, null_mut},
        slice::from_raw_parts,
    };

    use libafl_asan::{expect_panic, hooks::strdup::strdup};

    #[test]
    fn test_strdup_cs_null() {
        expect_panic();
        unsafe { strdup(null() as *const c_char) };
        unreachable!();
    }

    #[test]
    fn test_strdup_cs_empty() {
        let data = c"";
        let ret = unsafe { strdup(data.as_ptr() as *const c_char) };
        assert_ne!(ret, null_mut());
        assert_eq!(unsafe { *ret }, 0);
    }

    #[test]
    fn test_strdup_full() {
        let data = c"abcdefghij";
        let ret = unsafe { strdup(data.as_ptr() as *const c_char) };
        assert_ne!(ret, null_mut());
        data.to_bytes()
            .iter()
            .zip(unsafe { from_raw_parts(ret as *const u8, data.count_bytes()) })
            .for_each(|(x, y)| assert_eq!(x, y));
    }
}
