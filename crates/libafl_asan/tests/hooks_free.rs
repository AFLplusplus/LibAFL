#[cfg(test)]
#[cfg(feature = "hooks")]
mod tests {
    use core::ptr::null_mut;

    use libafl_asan::hooks::{free::free, malloc::malloc};

    #[test]
    fn test_free_null() {
        unsafe { free(null_mut()) };
    }

    #[test]
    fn test_free_buff() {
        let p = unsafe { malloc(10) };
        unsafe { free(p) }
    }
}
