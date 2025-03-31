#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::{c_int, c_void},
        ptr::null_mut,
    };

    use asan::{expect_panic, hooks::rawmemchr::rawmemchr};

    #[test]
    fn test_rawmemchr_null_buffer() {
        expect_panic();
        unsafe { rawmemchr(null_mut(), 0) };
        unreachable!()
    }

    #[test]
    fn test_rawmemchr_find_first() {
        let data = "abcdefghij".as_bytes();
        let c = 'a' as c_int;
        let ret = unsafe { rawmemchr(data.as_ptr() as *const c_void, c) };
        assert_eq!(ret, data.as_ptr() as *mut c_void);
    }

    #[test]
    fn test_rawmemchr_find_last() {
        let data = "abcdefghij".as_bytes();
        let c = 'j' as c_int;
        let ret = unsafe { rawmemchr(data.as_ptr() as *const c_void, c) };
        assert_eq!(ret, unsafe {
            data.as_ptr().add(data.len() - 1) as *mut c_void
        });
    }

    #[test]
    fn test_rawmemchr_find_mid() {
        let data = "abcdefghij".as_bytes();
        let c = 'e' as c_int;
        let ret = unsafe { rawmemchr(data.as_ptr() as *const c_void, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(4) as *mut c_void });
    }

    #[test]
    fn test_rawmemchr_find_repeated() {
        let data = "ababababab".as_bytes();
        let c = 'b' as c_int;
        let ret = unsafe { rawmemchr(data.as_ptr() as *const c_void, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(1) as *mut c_void });
    }
}
