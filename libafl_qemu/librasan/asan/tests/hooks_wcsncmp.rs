#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::null;

    use asan::{expect_panic, hooks::wcsncmp::wcsncmp, wchar_t};
    use widestring::widecstr;

    #[test]
    fn test_wcsncmp_zero_length() {
        expect_panic();
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
}
