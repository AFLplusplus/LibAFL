#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{ffi::c_char, ptr::null};

    use libafl_asan::{expect_panic, hooks::strncmp::strncmp};

    #[test]
    fn test_strncmp_zero_length() {
        let ret = unsafe { strncmp(null(), null(), 0) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strncmp_null_s1() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strncmp(null(), data.as_ptr() as *const c_char, data.len()) };
        unreachable!();
    }

    #[test]
    fn test_strncmp_null_s2() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { strncmp(data.as_ptr() as *const c_char, null(), data.len()) };
        unreachable!();
    }

    #[test]
    fn test_strncmp_eq() {
        let data = [1u8; 10];
        let ret = unsafe {
            strncmp(
                data.as_ptr() as *const c_char,
                data.as_ptr() as *const c_char,
                data.len(),
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strncmp_zero_length_both() {
        let data = [0u8; 10];
        let ret = unsafe {
            strncmp(
                data.as_ptr() as *const c_char,
                data.as_ptr() as *const c_char,
                data.len(),
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strncmp_zero_length_s1() {
        let data1 = [0u8; 10];
        let data2 = [1u8; 10];
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data1.len(),
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_strncmp_zero_length_s2() {
        let data1 = [1u8; 10];
        let data2 = [0u8; 10];
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data1.len(),
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_strncmp_eq_string() {
        let data1 = c"abcdefghij";
        let data2 = c"abcdefghij";
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data1.count_bytes(),
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strncmp_s1_shorter() {
        let data1 = c"abcdefghi";
        let data2 = c"abcdefghij";
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data2.count_bytes(),
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_strncmp_s1_longer() {
        let data1 = c"abcdefghij";
        let data2 = c"abcdefghi";
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data1.count_bytes(),
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_strncmp_s1_less_than() {
        let data1 = c"abcdefghii";
        let data2 = c"abcdefghij";
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data1.count_bytes(),
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_strncmp_s1_greater_than() {
        let data1 = c"abcdefghik";
        let data2 = c"abcdefghij";
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data1.count_bytes(),
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_strncmp_case_not_ignored() {
        let data1 = c"abcdefghijklmnopqrstuvwxyz";
        let data2 = c"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data1.count_bytes(),
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_strncmp_differ_after_length() {
        let data1 = c"abcdefghijXYZ";
        let data2 = c"abcdefghijUVW";
        let ret = unsafe {
            strncmp(
                data1.as_ptr() as *const c_char,
                data2.as_ptr() as *const c_char,
                data1.count_bytes() - 3,
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_strncmp_bounds() {
        use libafl_asan::{asan_alloc, asan_dealloc};

        unsafe {
            let p1 = asan_alloc(4, 8) as *mut u8;
            let p2 = asan_alloc(4, 8) as *mut u8;
            core::slice::from_raw_parts_mut(p1, 4).copy_from_slice(b"abcd");
            core::slice::from_raw_parts_mut(p2, 4).copy_from_slice(b"abcd");
            assert_eq!(strncmp(p1 as *const c_char, p2 as *const c_char, 4), 0);

            let short = asan_alloc(1, 8) as *mut u8;
            *short = b'z';
            assert!(strncmp(c"a".as_ptr(), short as *const c_char, 10) < 0);

            let nul_buf = asan_alloc(3, 8) as *mut u8;
            core::slice::from_raw_parts_mut(nul_buf, 3).copy_from_slice(b"ab\0");
            assert_eq!(strncmp(nul_buf as *const c_char, c"ab".as_ptr(), 10), 0);
            assert!(strncmp(c"\x80".as_ptr(), c"\x7f".as_ptr(), 1) > 0);

            asan_dealloc(nul_buf.cast());
            asan_dealloc(short.cast());
            asan_dealloc(p2.cast());
            asan_dealloc(p1.cast());
        }
    }
}
