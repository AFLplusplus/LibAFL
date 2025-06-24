#[cfg(test)]
#[cfg(all(feature = "hooks", feature = "libc"))]
mod tests {
    use core::{
        ffi::{c_char, c_int},
        ptr::null_mut,
    };

    use libafl_asan::{expect_panic, hooks::fgets::fgets};
    use libc::FILE;

    #[test]
    fn test_read_null_stream() {
        let mut buf = [0u8; 10];
        expect_panic();

        unsafe {
            fgets(
                buf.as_mut_ptr() as *mut c_char,
                buf.len() as c_int,
                null_mut(),
            )
        };
        unreachable!();
    }

    #[test]
    fn test_read_null_buff() {
        let stream = 0xdeadface as *mut FILE;
        expect_panic();

        unsafe { fgets(null_mut(), 10, stream) };
        unreachable!();
    }
}
