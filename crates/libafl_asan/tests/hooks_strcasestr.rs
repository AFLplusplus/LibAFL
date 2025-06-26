#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_char,
        ptr::{null, null_mut},
    };

    use libafl_asan::{expect_panic, hooks::strcasestr::strcasestr};

    #[test]
    fn test_strcasestr_null_s1() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strcasestr(null(), data.as_ptr() as *const c_char) };
        unreachable!();
    }

    #[test]
    fn test_strcasestr_null_s2() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strcasestr(data.as_ptr() as *const c_char, null()) };
        unreachable!();
    }

    #[test]
    fn test_strcasestr_ct_too_long() {
        let data1 = c"abcdefghij";
        let data2 = c"abcdefghijk";
        let ret = unsafe {
            strcasestr(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_strcasestr_found_at_start() {
        let data1 = c"abcdefghijk";
        let data2 = c"abc";
        let ret = unsafe {
            strcasestr(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, data1.as_ptr() as *mut c_char);
    }

    #[test]
    fn test_strcasestr_found_at_end() {
        let data1 = c"abcdefghijk";
        let data2 = c"ijk";
        let ret = unsafe {
            strcasestr(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, unsafe {
            data1
                .as_ptr()
                .add(data1.count_bytes() - data2.count_bytes()) as *mut c_char
        });
    }

    #[test]
    fn test_strcasestr_found_in_middle() {
        let data1 = c"abcdefghijk";
        let data2 = c"def";
        let ret = unsafe {
            strcasestr(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, unsafe { data1.as_ptr().add(3) as *mut c_char });
    }

    #[test]
    fn test_strcasestr_ignores_case() {
        let data1 = c"abcdefghijklmnopqrstuvwxyz";
        let data2 = c"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let ret = unsafe {
            strcasestr(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
            )
        };
        assert_eq!(ret, data1.as_ptr() as *mut c_char);
    }
}
