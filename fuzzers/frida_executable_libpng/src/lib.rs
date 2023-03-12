use std::process::exit;

mod fuzzer;

#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: extern fn(isize, *const *const char) -> isize,
    _argc: isize,
    _argv:*const *const char
) {
    /*let exit_code = main(_argc, _argv);
    exit((exit_code as isize).try_into().unwrap());*/
    unsafe {
        fuzzer::lib(main);
    }
}