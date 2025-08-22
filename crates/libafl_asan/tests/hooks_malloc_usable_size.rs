#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::null_mut;

    use libafl_asan::hooks::{malloc::malloc, malloc_usable_size::malloc_usable_size};

    #[test]
    fn test_malloc_usable_size_null() {
        let ret = unsafe { malloc_usable_size(null_mut()) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_malloc_usable_size_buff() {
        let p = unsafe { malloc(10) };
        let ret = unsafe { malloc_usable_size(p) };
        assert_eq!(ret, 10);
    }
}
