#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::{c_char, c_int},
        ptr::null,
    };

    use asan::{expect_panic, hooks::strchrnul::strchrnul};

    #[test]
    fn test_strchrnul_zero_length() {
        let data = c"";
        let ret = unsafe { strchrnul(data.as_ptr() as *const c_char, 0x88) };
        assert_eq!(ret, data.as_ptr() as *mut c_char);
    }

    #[test]
    fn test_strchrnul_null_buffer() {
        expect_panic();
        unsafe { strchrnul(null(), 0x88) };
        unreachable!()
    }

    #[test]
    fn test_strchrnul_find_first() {
        let data = c"abcdefghij";
        let c = 'a' as c_int;
        let ret = unsafe { strchrnul(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, data.as_ptr() as *mut c_char);
    }

    #[test]
    fn test_strchrnul_find_last() {
        let data = c"abcdefghij";
        let c = 'j' as c_int;
        let ret = unsafe { strchrnul(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, unsafe {
            data.as_ptr().add(data.count_bytes() - 1) as *mut c_char
        });
    }

    #[test]
    fn test_strchrnul_find_mid() {
        let data = c"abcdefghij";
        let c = 'e' as c_int;
        let ret = unsafe { strchrnul(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(4) as *mut c_char });
    }

    #[test]
    fn test_strchrnul_find_repeated() {
        let data = c"ababababab";
        let c = 'b' as c_int;
        let ret = unsafe { strchrnul(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(1) as *mut c_char });
    }

    #[test]
    fn test_strchrnul_not_found() {
        let data = c"abcdefghij";
        let c = 'k' as c_int;
        let ret = unsafe { strchrnul(data.as_ptr() as *const c_char, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(data.count_bytes()) }
            as *mut c_char);
    }
}
