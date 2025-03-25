#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_int,
        ptr::{null, null_mut},
    };

    use asan::{expect_panic, hooks::wcschr::wcschr, wchar_t};
    use widestring::widecstr;

    #[test]
    fn test_wcschr_zero_length() {
        let data = widecstr!("");
        let ret = unsafe { wcschr(data.as_ptr() as *const wchar_t, 0x88) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_wcschr_null_buffer() {
        expect_panic();
        unsafe { wcschr(null(), 0x88) };
        unreachable!()
    }

    #[test]
    fn test_wcschr_find_first() {
        let data = widecstr!("abcdefghij");
        let c = 'a' as c_int;
        let ret = unsafe { wcschr(data.as_ptr() as *const wchar_t, c) };
        assert_eq!(ret, data.as_ptr() as *mut wchar_t);
    }

    #[test]
    fn test_wcschr_find_last() {
        let data = widecstr!("abcdefghij");
        let c = 'j' as c_int;
        let ret = unsafe { wcschr(data.as_ptr() as *const wchar_t, c) };
        assert_eq!(ret, unsafe {
            data.as_ptr().add(data.len() - 1) as *mut wchar_t
        });
    }

    #[test]
    fn test_wcschr_find_mid() {
        let data = widecstr!("abcdefghij");
        let c = 'e' as c_int;
        let ret = unsafe { wcschr(data.as_ptr() as *const wchar_t, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(4) as *mut wchar_t });
    }

    #[test]
    fn test_wcschr_find_repeated() {
        let data = widecstr!("ababababab");
        let c = 'b' as c_int;
        let ret = unsafe { wcschr(data.as_ptr() as *const wchar_t, c) };
        assert_eq!(ret, unsafe { data.as_ptr().add(1) as *mut wchar_t });
    }

    #[test]
    fn test_wcschr_not_found() {
        let data = widecstr!("abcdefghij");
        let c = 'k' as c_int;
        let ret = unsafe { wcschr(data.as_ptr() as *const wchar_t, c) };
        assert_eq!(ret, null_mut());
    }
}
