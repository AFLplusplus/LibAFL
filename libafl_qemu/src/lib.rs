use std::env;

pub mod amd64;
pub mod x86;

pub mod elf;
pub mod hooks;

#[cfg(target_os = "linux")]
pub mod executor;
#[cfg(target_os = "linux")]
pub use executor::QemuExecutor;

#[cfg(target_os = "linux")]
pub mod emu;
#[cfg(target_os = "linux")]
pub use emu::*;

#[must_use]
pub fn filter_qemu_args() -> Vec<String> {
    let mut args = vec![env::args().next().unwrap()];
    let mut args_iter = env::args();

    while let Some(arg) = args_iter.next() {
        if arg.starts_with("--libafl") {
            args.push(arg);
            args.push(args_iter.next().unwrap());
        } else if arg.starts_with("-libafl") {
            args.push("-".to_owned() + &arg);
            args.push(args_iter.next().unwrap());
        }
    }
    args
}
