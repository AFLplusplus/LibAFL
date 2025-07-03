#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::null;

    use libafl_asan::{expect_panic, hooks::wcscmp::wcscmp, wchar_t};
    use widestring::widecstr;

    #[test]
    fn test_wcscmp_null_s1() {
        expect_panic();
        let data = [0u16; 10];
        unsafe { wcscmp(null(), data.as_ptr() as *const wchar_t) };
        unreachable!();
    }

    #[test]
    fn test_wcscmp_null_s2() {
        expect_panic();
        let data = [0u16; 10];
        unsafe { wcscmp(data.as_ptr() as *const wchar_t, null()) };
        unreachable!();
    }

    #[test]
    fn test_wcscmp_eq() {
        let data = [1u16; 10];
        let ret = unsafe {
            wcscmp(
                data.as_ptr() as *const wchar_t,
                data.as_ptr() as *const wchar_t,
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcscmp_zero_length_both() {
        let data = [0u16; 10];
        let ret = unsafe {
            wcscmp(
                data.as_ptr() as *const wchar_t,
                data.as_ptr() as *const wchar_t,
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcscmp_zero_length_s1() {
        let data1 = [0u16; 10];
        let data2 = [1u16; 10];
        let ret = unsafe {
            wcscmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_wcscmp_zero_length_s2() {
        let data1 = [1u16; 10];
        let data2 = [0u16; 10];
        let ret = unsafe {
            wcscmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_wcscmp_eq_string() {
        let data1 = widecstr!("abcdefghij");
        let data2 = widecstr!("abcdefghij");
        let ret = unsafe {
            wcscmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
            )
        };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcscmp_s1_shorter() {
        let data1 = widecstr!("abcdefghi");
        let data2 = widecstr!("abcdefghij");
        let ret = unsafe {
            wcscmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_wcscmp_s1_longer() {
        let data1 = widecstr!("abcdefghij");
        let data2 = widecstr!("abcdefghi");
        let ret = unsafe {
            wcscmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_wcscmp_s1_less_than() {
        let data1 = widecstr!("abcdefghii");
        let data2 = widecstr!("abcdefghij");
        let ret = unsafe {
            wcscmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
            )
        };
        assert!(ret < 0);
    }

    #[test]
    fn test_wcscmp_s1_greater_than() {
        let data1 = widecstr!("abcdefghik");
        let data2 = widecstr!("abcdefghij");
        let ret = unsafe {
            wcscmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
            )
        };
        assert!(ret > 0);
    }

    #[test]
    fn test_wcscmp_case_not_ignored() {
        let data1 = widecstr!("abcdefghijklmnopqrstuvwxyz");
        let data2 = widecstr!("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let ret = unsafe {
            wcscmp(
                data1.as_ptr() as *const wchar_t,
                data2.as_ptr() as *const wchar_t,
            )
        };
        assert!(ret > 0);
    }
}
