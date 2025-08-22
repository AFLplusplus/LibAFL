use core::ffi::c_int;

use rustix::process::{Signal, kill_current_process_group};
use syscalls::{Sysno, syscall1};

pub fn abort() -> ! {
    kill_current_process_group(Signal::ABORT).unwrap();
    unreachable!();
}

pub fn exit(status: c_int) -> ! {
    unsafe { syscall1(Sysno::exit_group, status as usize) }.unwrap();
    unreachable!();
}
