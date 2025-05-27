#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::null;

    use asan::{expect_panic, hooks::wcsnlen::wcsnlen, wchar_t};
    use widestring::widecstr;

    #[test]
    fn test_wcsnlen_zero_length() {
        let ret = unsafe { wcsnlen(null() as *const wchar_t, 0) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcsnlen_cs_null() {
        expect_panic();
        unsafe { wcsnlen(null() as *const wchar_t, 10) };
        unreachable!();
    }

    #[test]
    fn test_wcsnlen_cs_empty() {
        let data = widecstr!("");
        let ret = unsafe { wcsnlen(data.as_ptr() as *const wchar_t, 10) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_wcsnlen_full() {
        let data = widecstr!("abcdefghij");
        let ret = unsafe { wcsnlen(data.as_ptr() as *const wchar_t, data.len()) };
        assert_eq!(ret, 10);
    }

    #[test]
    fn test_wcsnlen_partial() {
        let data = widecstr!("abcdefghij");
        let ret = unsafe { wcsnlen(data.as_ptr() as *const wchar_t, 5) };
        assert_eq!(ret, 5);
    }
}
