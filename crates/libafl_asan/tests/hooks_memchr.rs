#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::{c_int, c_void},
        ptr::null_mut,
    };

    use libafl_asan::{expect_panic, hooks::memchr::memchr};

    #[test]
    fn test_memchr_zero_length() {
        let ret = unsafe { memchr(null_mut(), 0, 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_memchr_null_buffer() {
        expect_panic();
        unsafe { memchr(null_mut(), 0, 10) };
        unreachable!()
    }

    #[test]
    fn test_memchr_find_first() {
        let data = "abcdefghij".as_bytes();
        let c = 'a' as c_int;
        let ret = unsafe { memchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, data.as_ptr() as *mut c_void);
    }

    #[test]
    fn test_memchr_find_last() {
        let data = "abcdefghij".as_bytes();
        let c = 'j' as c_int;
        let ret = unsafe { memchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, unsafe {
            data.as_ptr().add(data.len() - 1) as *mut c_void
        });
    }

    #[test]
    fn test_memchr_find_mid() {
        let data = "abcdefghij".as_bytes();
        let c = 'e' as c_int;
        let ret = unsafe { memchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, unsafe { data.as_ptr().add(4) as *mut c_void });
    }

    #[test]
    fn test_memchr_find_repeated() {
        let data = "ababababab".as_bytes();
        let c = 'b' as c_int;
        let ret = unsafe { memchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, unsafe { data.as_ptr().add(1) as *mut c_void });
    }

    #[test]
    fn test_memchr_not_found() {
        let data = "abcdefghij".as_bytes();
        let c = 'k' as c_int;
        let ret = unsafe { memchr(data.as_ptr() as *const c_void, c, data.len()) };
        assert_eq!(ret, null_mut());
    }
}
