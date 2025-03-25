#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::null_mut;

    use asan::{expect_panic, hooks::wmemchr::wmemchr, wchar_t};
    use widestring::widecstr;

    #[test]
    fn test_wmemchr_zero_length() {
        let ret = unsafe { wmemchr(null_mut(), 0, 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_wmemchr_null_buffer() {
        expect_panic();
        unsafe { wmemchr(null_mut(), 0, 10) };
        unreachable!()
    }

    #[test]
    fn test_wmemchr_find_first() {
        let data = widecstr!("abcdefghij");
        let c = 'a' as wchar_t;
        let ret = unsafe { wmemchr(data.as_ptr() as *const wchar_t, c, data.len()) };
        assert_eq!(ret, data.as_ptr() as *mut wchar_t);
    }

    #[test]
    fn test_wmemchr_find_last() {
        let data = widecstr!("abcdefghij");
        let c = 'j' as wchar_t;
        let ret = unsafe { wmemchr(data.as_ptr() as *const wchar_t, c, data.len()) };
        assert_eq!(ret, unsafe {
            data.as_ptr().add(data.len() - 1) as *mut wchar_t
        });
    }

    #[test]
    fn test_wmemchr_find_mid() {
        let data = widecstr!("abcdefghij");
        let c = 'e' as wchar_t;
        let ret = unsafe { wmemchr(data.as_ptr() as *const wchar_t, c, data.len()) };
        assert_eq!(ret, unsafe { data.as_ptr().add(4) as *mut wchar_t });
    }

    #[test]
    fn test_wmemchr_find_repeated() {
        let data = widecstr!("ababababab");
        let c = 'b' as wchar_t;
        let ret = unsafe { wmemchr(data.as_ptr() as *const wchar_t, c, data.len()) };
        assert_eq!(ret, unsafe { data.as_ptr().add(1) as *mut wchar_t });
    }

    #[test]
    fn test_wmemchr_not_found() {
        let data = widecstr!("abcdefghij");
        let c = 'k' as wchar_t;
        let ret = unsafe { wmemchr(data.as_ptr() as *const wchar_t, c, data.len()) };
        assert_eq!(ret, null_mut());
    }
}
