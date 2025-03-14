use libafl_bolts::HasLen;
use libafl_qemu_sys::GuestAddr;

use crate::{
    Qemu, SYS_execve, SYS_read,
    emu::EmulatorModules,
    modules::{EmulatorModule, EmulatorModuleTuple},
    qemu::{Hook, SyscallHookResult},
};

/// This module hijacks any read to buffer from stdin, and instead fill the buffer from the specified input address
/// This is useful when your binary target reads the input from the stdin.
/// With this you can just fuzz more like afl++
/// You need to use this with snapshot module!
#[derive(Debug, Default)]
pub struct RedirectStdinModule {
    input_addr: GuestAddr,
    read: usize,
    total: usize,
}

impl RedirectStdinModule {
    #[must_use]
    /// constuctor
    pub fn new() -> Self {
        Self {
            input_addr: 0,
            read: 0,
            total: 0,
        }
    }

    /// set where the input is placed
    pub fn set_input_addr(&mut self, input_addr: GuestAddr) {
        self.input_addr = input_addr;
    }
}

impl<I, S> EmulatorModule<I, S> for RedirectStdinModule
where
    I: Unpin + HasLen,
    S: Unpin,
{
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.pre_syscalls(Hook::Function(syscall_read_hook::<ET, I, S>));
    }

    fn pre_exec<ET>(
        &mut self,
        _qemu: Qemu,
        _emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
        input: &I,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        self.total = input.len();
    }
}

#[expect(clippy::too_many_arguments)]
fn syscall_read_hook<ET, I, S>(
    _qemu: Qemu,
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    _state: Option<&mut S>,
    syscall: i32,
    x0: GuestAddr,
    x1: GuestAddr,
    x2: GuestAddr,
    _x3: GuestAddr,
    _x4: GuestAddr,
    _x5: GuestAddr,
    _x6: GuestAddr,
    _x7: GuestAddr,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + HasLen,
    S: Unpin,
{
    debug_assert!(i32::try_from(SYS_execve).is_ok());
    let h = emulator_modules.get_mut::<RedirectStdinModule>().unwrap();
    let addr = h.input_addr;

    if syscall == SYS_read as i32 && x0 == 0 {
        /*
        println!(
            "Is sys read {:x} {} {:x} {:x} {} {} {} {} {}",
            rip, x0, x1, x2, x3, x4, x5, x6, x7
        );
        */
        let size = unsafe {
            let mut src = addr as *mut u8;
            src = src.wrapping_add(h.read as usize);
            let dst = x1 as *mut u8;
            let size = std::cmp::min(x2, (h.total - h.read) as u64);
            // println!("copying {:p} {:p} {}", src, dst, size);
            dst.copy_from(src, size as usize);
            size
        };
        // println!("copied {}", size);
        h.read += size as usize;
        return SyscallHookResult::new(Some(size));
    }
    SyscallHookResult::new(None)
}
