#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::null;

    use libafl_asan::{expect_panic, hooks::wcsncmp::wcsncmp, wchar_t};
    use widestring::widecstr;

    #[test]
    fn test_wcsncmp_zero_length() {
        let ret = unsafe { wcsncmp(null(), null(), 0) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcsncmp_null_s1() {
        expect_panic();
        let data = [0u32; 10];
        unsafe { wcsncmp(null(), data.as_ptr() as *const wchar_t, data.len()) };
        unreachable!();
    }

    #[test]
    fn test_wcsncmp_null_s2() {
        expect_panic();
        let data = [0u32; 10];
        unsafe { wcsncmp(data.as_ptr() as *const wchar_t, null(), data.len()) };
        unreachable!();
    }

    #[test]
    fn test_wcsncmp_eq() {
        let data = [1u32; 10];
        let ret = unsafe {
            wcsncmp(
                data.as_ptr() as *const wchar_t,
                data.as_ptr() as *const wchar_t,
                data.len(),
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcsncmp_zero_length_both() {
        let data = [0u32; 10];
        let ret = unsafe {
            wcsncmp(
                data.as_ptr() as *const wchar_t,
                data.as_ptr() as *const wchar_t,
                data.len(),
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcsncmp_zero_length_s1() {
        let data1 = [0u32; 10];
        let data2 = [1u32; 10];
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data1.len(),
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_wcsncmp_zero_length_s2() {
        let data1 = [1u32; 10];
        let data2 = [0u32; 10];
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data1.len(),
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_wcsncmp_eq_string() {
        let data1 = widecstr!("abcdefghij");
        let data2 = widecstr!("abcdefghij");
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data1.len(),
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcsncmp_s1_shorter() {
        let data1 = widecstr!("abcdefghi");
        let data2 = widecstr!("abcdefghij");
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data2.len(),
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_wcsncmp_s1_longer() {
        let data1 = widecstr!("abcdefghij");
        let data2 = widecstr!("abcdefghi");
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data1.len(),
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_wcsncmp_s1_less_than() {
        let data1 = widecstr!("abcdefghii");
        let data2 = widecstr!("abcdefghij");
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data1.len(),
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_wcsncmp_s1_greater_than() {
        let data1 = widecstr!("abcdefghik");
        let data2 = widecstr!("abcdefghij");
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data1.len(),
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_wcsncmp_case_not_ignored() {
        let data1 = widecstr!("abcdefghijklmnopqrstuvwxyz");
        let data2 = widecstr!("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data1.len(),
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_wcsncmp_differ_after_length() {
        let data1 = widecstr!("abcdefghijXYZ");
        let data2 = widecstr!("abcdefghijUVW");
        let ret = unsafe {
            wcsncmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
                data1.len() - 3,
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcsncmp_bounds() {
        use libafl_asan::{asan_alloc, asan_dealloc};

        unsafe {
            let elem_sz = size_of::<wchar_t>();
            let align = align_of::<wchar_t>().max(8);
            let p1 = asan_alloc(4 * elem_sz, align) as *mut wchar_t;
            let p2 = asan_alloc(4 * elem_sz, align) as *mut wchar_t;
            for i in 0..4 {
                *p1.add(i) = (0x41 + i as i32) as wchar_t;
                *p2.add(i) = (0x41 + i as i32) as wchar_t;
            }
            assert_eq!(wcsncmp(p1, p2, 4), 0);

            let short = asan_alloc(elem_sz, align) as *mut wchar_t;
            *short = 0x7A as wchar_t;
            assert!(wcsncmp(widecstr!("a").as_ptr() as *const wchar_t, short, 10) < 0);

            let nul_buf = asan_alloc(3 * elem_sz, align) as *mut wchar_t;
            *nul_buf = 0x61 as wchar_t;
            *nul_buf.add(1) = 0x62 as wchar_t;
            *nul_buf.add(2) = 0 as wchar_t;
            assert_eq!(
                wcsncmp(nul_buf, widecstr!("ab").as_ptr() as *const wchar_t, 10),
                0
            );
            let min_w = [wchar_t::MIN, 0];
            let pos_w = [1 as wchar_t, 0];
            assert!(wcsncmp(min_w.as_ptr(), pos_w.as_ptr(), 1) < 0);

            asan_dealloc(nul_buf.cast());
            asan_dealloc(short.cast());
            asan_dealloc(p2.cast());
            asan_dealloc(p1.cast());
        }
    }
}
