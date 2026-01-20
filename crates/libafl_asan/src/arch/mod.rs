#[cfg(feature = "nostd")]
use log::error;

#[cfg(feature = "nostd")]
use crate::exit::abort;

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "arm")]
mod arm;

#[cfg(feature = "nostd")]
#[unsafe(no_mangle)]
extern "C" fn _Unwind_Resume() {
    error!("_Unwind_Resume");
    abort();
}
