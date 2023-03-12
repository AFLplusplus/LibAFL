use std::process::exit;

mod fuzzer;

#[no_mangle]
fn __libc_csu_fini() {}

#[no_mangle]
fn __libc_csu_init() {}

#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: extern fn(isize, *const *const u8) -> isize,
    _argc: isize,
    _argv:*const *const char
) {
    /*let exit_code = main(_argc, _argv);
    exit((exit_code as isize).try_into().unwrap());*/
    unsafe {
        fuzzer::lib(main);
    }

    exit(0);
}