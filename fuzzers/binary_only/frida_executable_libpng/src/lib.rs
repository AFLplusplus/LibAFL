#![allow(clippy::missing_safety_doc)]
use std::mem::transmute;

use libc::{c_void, dlsym, RTLD_NEXT};

mod fuzzer;

type LibcStartMainFunc = fn(
    unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32,
    i32,
    *const *const char,
    extern "C" fn(i32, *const *const u8, *const *const u8) -> i32,
    extern "C" fn(),
    extern "C" fn(),
    *mut c_void,
) -> i32;

type MainFunc = extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;

extern "C" fn _dummy_main(_argc: i32, _argv: *const *const u8, _env: *const *const u8) -> i32 {
    0
}

static mut ORIG_MAIN: MainFunc = _dummy_main;

#[no_mangle]
pub unsafe extern "C" fn main_hook(
    _argc: i32,
    _argv: *const *const u8,
    _env: *const *const u8,
) -> i32 {
    fuzzer::lib(ORIG_MAIN);
    0
}

#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: extern "C" fn(i32, *const *const u8, *const *const u8) -> i32,
    argc: i32,
    argv: *const *const char,
    init: extern "C" fn(i32, *const *const u8, *const *const u8) -> i32,
    fini: extern "C" fn(),
    rtld_fini: extern "C" fn(),
    stack_end: *mut c_void,
) -> i32 {
    unsafe {
        ORIG_MAIN = main;

        let orig_libc_start_main_addr: *mut c_void =
            dlsym(RTLD_NEXT, c"__libc_start_main".as_ptr());

        let orig_libc_start_main: LibcStartMainFunc = transmute(orig_libc_start_main_addr);

        orig_libc_start_main(main_hook, argc, argv, init, fini, rtld_fini, stack_end)
    }
}
