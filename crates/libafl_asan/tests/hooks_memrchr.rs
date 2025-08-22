#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::{c_int, c_void},
        ptr::null_mut,
    };

    use libafl_asan::{expect_panic, hooks::memrchr::memrchr};

    #[test]
    fn test_memrchr_zero_length() {
        let ret = unsafe { memrchr(null_mut(), 0, 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_memrchr_null_buffer() {
        expect_panic();
        unsafe { memrchr(null_mut(), 0, 10) };
        unreachable!()
    }

    #[test]
    fn test_memrchr_find_first() {
        let data = "abcdefghij".as_bytes();
        let c = 'a' as c_int;
        let ret = unsafe { memrchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, data.as_ptr() as *mut c_void);
    }

    #[test]
    fn test_memrchr_find_last() {
        let data = "abcdefghij".as_bytes();
        let c = 'j' as c_int;
        let ret = unsafe { memrchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, unsafe {
            data.as_ptr().add(data.len() - 1) as *mut c_void
        });
    }

    #[test]
    fn test_memrchr_find_mid() {
        let data = "abcdefghij".as_bytes();
        let c = 'e' as c_int;
        let ret = unsafe { memrchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, unsafe { data.as_ptr().add(4) as *mut c_void });
    }

    #[test]
    fn test_memrchr_find_repeated() {
        let data = "ababababab".as_bytes();
        let c = 'b' as c_int;
        let ret = unsafe { memrchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, unsafe {
            data.as_ptr().add(data.len() - 1) as *mut c_void
        });
    }

    #[test]
    fn test_memrchr_not_found() {
        let data = "abcdefghij".as_bytes();
        let c = 'k' as c_int;
        let ret = unsafe { memrchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, null_mut());
    }
}
