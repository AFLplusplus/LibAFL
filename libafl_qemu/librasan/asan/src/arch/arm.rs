use log::error;

use crate::exit::abort;

#[no_mangle]
extern "C" fn __aeabi_unwind_cpp_pr0() {
    error!("__aeabi_unwind_cpp_pr0");
    abort();
}

#[no_mangle]
extern "C" fn __aeabi_unwind_cpp_pr1() {
    error!("__aeabi_unwind_cpp_pr1");
    abort();
}
