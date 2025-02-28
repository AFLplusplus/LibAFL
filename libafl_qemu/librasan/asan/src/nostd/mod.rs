//! # nostd
//! This module is used to support `no_std` environments.
use core::panic::PanicInfo;

use log::error;

use crate::exit::abort;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("Panic!");
    error!("INFO: {}", info);
    abort();
}

#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {
    error!("rust_eh_personality");
    abort();
}
