#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::{null, null_mut};

    use libafl_asan::{expect_panic, hooks::wcscpy::wcscpy, wchar_t};
    use widestring::widecstr;

    #[test]
    fn test_wcscpy_null_s() {
        expect_panic();
        let data = [0u16; 10];
        unsafe { wcscpy(null_mut(), data.as_ptr() as *const wchar_t) };
        unreachable!();
    }

    #[test]
    fn test_wcscpy_null_s2() {
        expect_panic();
        let data = [0u16; 10];
        unsafe { wcscpy(data.as_ptr() as *mut wchar_t, null()) };
        unreachable!();
    }

    #[test]
    fn test_wcscpy_zero_length_both() {
        let data = [0u16; 10];
        let ret = unsafe {
            wcscpy(
                data.as_ptr() as *mut wchar_t,
                data.as_ptr() as *const wchar_t,
            )
        };
        assert_eq!(ret, data.as_ptr() as *mut wchar_t);
    }

    #[test]
    fn test_wcscpy_copies() {
        let mut vec = widecstr!("abcdefghij").as_slice().to_vec();
        let s = vec.as_mut_slice();
        let ct = widecstr!("klmnop");
        let ret = unsafe { wcscpy(s.as_ptr() as *mut wchar_t, ct.as_ptr() as *const wchar_t) };
        assert_eq!(ret, s.as_ptr() as *mut wchar_t);
        ct.as_slice()
            .iter()
            .zip(s.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }
}
