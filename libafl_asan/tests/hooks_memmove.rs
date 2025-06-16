#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_void,
        ptr::{null, null_mut},
    };

    use libafl_asan::{expect_panic, hooks::memmove::memmove};

    #[test]
    fn test_memmove_zero_length() {
        let ret = unsafe { memmove(null_mut(), null_mut(), 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_memmove_src_null() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { memmove(null_mut(), data.as_ptr() as *const c_void, data.len()) };
        unreachable!();
    }

    #[test]
    fn test_memmove_dst_null() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { memmove(data.as_ptr() as *mut c_void, null(), data.len()) };
        unreachable!();
    }

    #[test]
    fn test_adjacent_1() {
        let data = [0u8; 20];
        let dest = data.as_ptr() as *mut c_void;
        let src = unsafe { data.as_ptr().add(10) as *const c_void };
        let ret = unsafe { memmove(dest, src, 10) };
        assert_eq!(ret, dest);
    }

    #[test]
    fn test_adjacent_2() {
        let data = [0u8; 20];
        let dest = unsafe { data.as_ptr().add(10) as *mut c_void };
        let src = data.as_ptr() as *const c_void;
        let ret = unsafe { memmove(dest, src, 10) };
        assert_eq!(ret, dest);
    }

    #[test]
    fn test_overlap_1() {
        let mut vec = "abcdefghijklmnopqrst".as_bytes().to_vec();
        let data = vec.as_mut_slice();
        let dest = data.as_ptr() as *mut c_void;
        let src = unsafe { data.as_ptr().add(9) as *const c_void };
        let ret = unsafe { memmove(dest, src, 10) };
        assert_eq!(ret, dest);
        let expected = "jklmnopqrsklmnopqrst".as_bytes();
        data.iter()
            .zip(expected.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }

    #[test]
    fn test_overlap_2() {
        let mut vec = "abcdefghijklmnopqrst".as_bytes().to_vec();
        let data = vec.as_mut_slice();
        let dest = unsafe { data.as_ptr().add(9) as *mut c_void };
        let src = data.as_ptr() as *const c_void;
        let ret = unsafe { memmove(dest, src, 10) };
        assert_eq!(ret, dest);
        let expected = "abcdefghiabcdefghijt".as_bytes();
        data.iter()
            .zip(expected.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }

    #[test]
    fn test_memmove_full() {
        let src = [0xffu8; 10];
        let dest = [0u8; 10];
        let ret = unsafe {
            memmove(
                dest.as_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                dest.len(),
            )
        };
        assert_eq!(ret, dest.as_ptr() as *mut c_void);
        src.iter()
            .zip(dest.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }

    #[test]
    fn test_memmove_partial() {
        let src = [0xffu8; 5];
        let dest = [0u8; 10];
        let ret = unsafe {
            memmove(
                dest.as_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                src.len(),
            )
        };
        assert_eq!(ret, dest.as_ptr() as *mut c_void);
        src.iter()
            .zip(dest.iter().take(src.len()))
            .for_each(|(x, y)| assert_eq!(*x, *y));
        dest.iter().skip(5).for_each(|x| assert_eq!(*x, 0));
    }
}
