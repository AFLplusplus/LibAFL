#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::{c_char, c_int},
        ptr::{null, null_mut},
    };

    use libafl_asan::{expect_panic, hooks::strchr::strchr};

    #[test]
    fn test_strchr_zero_length() {
        let data = c"";
        let ret = unsafe { strchr(data.as_ptr() as *const c_char, 0x88) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_strchr_null_buffer() {
        expect_panic();
        unsafe { strchr(null(), 0x88) };
        unreachable!()
    }

    #[test]
    fn test_strchr_find_first() {
        let data = c"abcdefghij";
        let c = 'a' as c_int;
        let ret = unsafe { strchr(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, data.as_ptr() as *mut c_char);
    }

    #[test]
    fn test_strchr_find_last() {
        let data = c"abcdefghij";
        let c = 'j' as c_int;
        let ret = unsafe { strchr(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, unsafe {
            data.as_ptr().add(data.count_bytes() - 1) as *mut c_char
        });
    }

    #[test]
    fn test_strchr_find_mid() {
        let data = c"abcdefghij";
        let c = 'e' as c_int;
        let ret = unsafe { strchr(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(4) as *mut c_char });
    }

    #[test]
    fn test_strchr_find_repeated() {
        let data = c"ababababab";
        let c = 'b' as c_int;
        let ret = unsafe { strchr(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(1) as *mut c_char });
    }

    #[test]
    fn test_strchr_not_found() {
        let data = c"abcdefghij";
        let c = 'k' as c_int;
        let ret = unsafe { strchr(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, null_mut());
    }
}
