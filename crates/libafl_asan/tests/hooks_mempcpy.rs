#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::{
        ffi::c_void,
        ptr::{null, null_mut},
    };

    use libafl_asan::{expect_panic, hooks::mempcpy::mempcpy};

    #[test]
    fn test_mempcpy_zero_length() {
        let ret = unsafe { mempcpy(null_mut(), null_mut(), 0) };
        assert_eq!(ret, null_mut());
    }

    #[test]
    fn test_mempcpy_src_null() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { mempcpy(null_mut(), data.as_ptr() as *const c_void, data.len()) };
        unreachable!();
    }

    #[test]
    fn test_mempcpy_dst_null() {
        expect_panic();
        let data = [0u8; 10];
        unsafe { mempcpy(data.as_ptr() as *mut c_void, null(), data.len()) };
        unreachable!();
    }

    #[test]
    fn test_adjacent_1() {
        let data = [0u8; 20];
        let dest = data.as_ptr() as *mut c_void;
        let src = unsafe { data.as_ptr().add(10) as *const c_void };
        let ret = unsafe { mempcpy(dest, src, 10) };
        assert_eq!(ret, unsafe { dest.add(10) });
    }

    #[test]
    fn test_adjacent_2() {
        let data = [0u8; 20];
        let dest = unsafe { data.as_ptr().add(10) as *mut c_void };
        let src = data.as_ptr() as *const c_void;
        let ret = unsafe { mempcpy(dest, src, 10) };
        assert_eq!(ret, unsafe { dest.add(10) });
    }

    #[test]
    fn test_overlap_1() {
        expect_panic();
        let data = [0u8; 20];
        let dest = data.as_ptr() as *mut c_void;
        let src = unsafe { data.as_ptr().add(9) as *const c_void };
        unsafe { mempcpy(dest, src, 10) };
        unreachable!();
    }

    #[test]
    fn test_overlap_2() {
        expect_panic();
        let data = [0u8; 20];
        let dest = unsafe { data.as_ptr().add(9) as *mut c_void };
        let src = data.as_ptr() as *const c_void;
        unsafe { mempcpy(dest, src, 10) };
        unreachable!();
    }

    #[test]
    fn test_mempcpy_full() {
        let src = [0xffu8; 10];
        let dest = [0u8; 10];
        let ret = unsafe {
            mempcpy(
                dest.as_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                dest.len(),
            )
        };
        assert_eq!(ret, unsafe { dest.as_ptr().add(dest.len()) as *mut c_void });
        src.iter()
            .zip(dest.iter())
            .for_each(|(x, y)| assert_eq!(*x, *y));
    }

    #[test]
    fn test_mempcpy_partial() {
        let src = [0xffu8; 5];
        let dest = [0u8; 10];
        let ret = unsafe {
            mempcpy(
                dest.as_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                src.len(),
            )
        };
        assert_eq!(ret, unsafe { dest.as_ptr().add(src.len()) as *mut c_void });
        src.iter()
            .zip(dest.iter().take(src.len()))
            .for_each(|(x, y)| assert_eq!(*x, *y));
        dest.iter().skip(5).for_each(|x| assert_eq!(*x, 0));
    }
}
