mod fuzzer;

#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: extern fn(isize, *const *const char) -> isize,
    _argc: isize,
    _argv:*const *const char
) {
    unsafe {
        fuzzer::lib(main);
    }
}