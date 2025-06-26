#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_void,
        ptr::{null, null_mut},
    };

    use libafl_asan::{expect_panic, hooks::memmem::memmem};

    #[test]
    fn test_memmem_needle_zero_length() {
        let haystack = [0u8; 10];
        let ret = unsafe {
            memmem(
                haystack.as_ptr() as *const c_void,
                haystack.len(),
                null(),
                0,
            )
        };
        assert_eq!(ret, haystack.as_ptr() as *mut c_void);
    }

    #[test]
    fn test_memmem_needle_too_long() {
        let haystack = [0u8; 10];
        let needle = [0u8; 11];
        let ret = unsafe {
            memmem(
                haystack.as_ptr() as *const c_void,
                haystack.len(),
                needle.as_ptr() as *const c_void,
                needle.len(),
            )
        };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_memmem_haystack_null() {
        expect_panic();
        let needle = [0u8; 10];
        unsafe { memmem(null(), 10, needle.as_ptr() as *const c_void, needle.len()) };
        unreachable!();
    }

    #[test]
    fn test_memmem_needle_null() {
        expect_panic();
        let haystack = [0u8; 10];
        unsafe {
            memmem(
                haystack.as_ptr() as *const c_void,
                haystack.len(),
                null(),
                10,
            )
        };
        unreachable!();
    }

    #[test]
    fn test_memmem_found_at_start() {
        let haystack = "abcdefghij".as_bytes();
        let needle = "abc".as_bytes();
        let ret = unsafe {
            memmem(
                haystack.as_ptr() as *const c_void,
                haystack.len(),
                needle.as_ptr() as *const c_void,
                needle.len(),
            )
        };
        assert_eq!(ret, haystack.as_ptr() as *mut c_void);
    }

    #[test]
    fn test_memmem_found_at_end() {
        let haystack = "abcdefghij".as_bytes();
        let needle = "hij".as_bytes();
        let ret = unsafe {
            memmem(
                haystack.as_ptr() as *const c_void,
                haystack.len(),
                needle.as_ptr() as *const c_void,
                needle.len(),
            )
        };
        assert_eq!(ret, unsafe {
            haystack.as_ptr().add(haystack.len() - needle.len()) as *mut c_void
        });
    }

    #[test]
    fn test_memmem_found_in_middle() {
        let haystack = "abcdefghij".as_bytes();
        let needle = "def".as_bytes();
        let ret = unsafe {
            memmem(
                haystack.as_ptr() as *const c_void,
                haystack.len(),
                needle.as_ptr() as *const c_void,
                needle.len(),
            )
        };
        assert_eq!(ret, unsafe { haystack.as_ptr().add(3) as *mut c_void });
    }

    #[test]
    fn test_memmem_not_found() {
        let haystack = "abcdefghij".as_bytes();
        let needle = "xyz".as_bytes();
        let ret = unsafe {
            memmem(
                haystack.as_ptr() as *const c_void,
                haystack.len(),
                needle.as_ptr() as *const c_void,
                needle.len(),
            )
        };
        assert_eq!(ret, null_mut());
    }
}
