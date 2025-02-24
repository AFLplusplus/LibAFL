use core::ffi::c_int;

use rustix::process::{kill_current_process_group, Signal};
use syscalls::{syscall1, Sysno};

pub fn abort() -> ! {
    kill_current_process_group(Signal::Abort).unwrap();
    unreachable!();
}

pub fn exit(status: c_int) -> ! {
    unsafe { syscall1(Sysno::exit_group, status as usize) }.unwrap();
    unreachable!();
}
