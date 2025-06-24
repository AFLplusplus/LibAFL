#[cfg(test)]
#[cfg(feature = "libc")]
mod tests {
    use core::ffi::{CStr, c_int, c_void};

    use libafl_asan::{
        GuestAddr,
        symbols::{
            Function, Symbols,
            dlsym::{DlSymSymbols, LookupTypeDefault},
        },
    };
    use libc::{off_t, size_t};

    #[derive(Debug)]
    struct FunctionMmap;

    impl Function for FunctionMmap {
        type Func =
            unsafe extern "C" fn(*mut c_void, size_t, c_int, c_int, c_int, off_t) -> *mut c_void;
        const NAME: &'static CStr = c"mmap";
    }

    #[derive(Debug)]
    struct FunctionMunmap;

    impl Function for FunctionMunmap {
        type Func = unsafe extern "C" fn(*mut c_void, size_t) -> c_int;
        const NAME: &'static CStr = c"munmap";
    }

    type DlSym = DlSymSymbols<LookupTypeDefault>;

    #[test]
    fn test_dlsym() {
        use libafl_asan::symbols::FunctionPointer;

        let mmap = DlSym::lookup(c"mmap").unwrap();
        let mmap2 = DlSym::lookup(c"mmap").unwrap();
        assert_eq!(mmap, mmap2);
        let fnmmap = FunctionMmap::as_ptr(mmap).unwrap();
        let mapping = unsafe {
            fnmmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        let addr = mapping as GuestAddr;
        assert!(addr & 0xfff == 0);
        let munmap = DlSym::lookup(c"munmap").unwrap();
        let munmap2 = DlSym::lookup(c"munmap").unwrap();
        assert_eq!(munmap, munmap2);
        let fnmunmap = FunctionMunmap::as_ptr(munmap).unwrap();
        let ret = unsafe { fnmunmap(mapping, 4096) };
        assert!(ret == 0);
    }
}
