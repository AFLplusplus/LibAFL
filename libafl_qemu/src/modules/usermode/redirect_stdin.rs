use core::fmt::Debug;

use libafl_bolts::HasLen;
use libafl_qemu_sys::GuestAddr;

#[cfg(not(cpu_target = "hexagon"))]
use crate::SYS_read;
use crate::{
    Qemu,
    emu::EmulatorModules,
    modules::{EmulatorModule, EmulatorModuleTuple},
    qemu::{Hook, SyscallHookResult},
};

#[cfg(cpu_target = "hexagon")]
/// Hexagon syscalls are not currently supported by the `syscalls` crate, so we just paste this here for now.
/// <https://github.com/qemu/qemu/blob/11be70677c70fdccd452a3233653949b79e97908/linux-user/hexagon/syscall_nr.h#L230>
#[expect(non_upper_case_globals)]
const SYS_read: u8 = 63;

/// This module hijacks any read to buffer from stdin, and instead fill the buffer from the specified input address
/// This is useful when your binary target reads the input from the stdin.
/// With this you can just fuzz more like afl++
/// You need to use this with snapshot module!
#[derive(Debug)]
pub struct RedirectStdinModule {
    input_addr: *const u8,
    read: usize,
    total: usize,
}

impl Default for RedirectStdinModule {
    fn default() -> Self {
        Self::new()
    }
}

impl RedirectStdinModule {
    #[must_use]
    /// constuctor
    pub fn new() -> Self {
        Self::with_input_addr(core::ptr::null())
    }

    #[must_use]
    /// Create with specified input address
    pub fn with_input_addr(addr: *const u8) -> Self {
        Self {
            input_addr: addr,
            read: 0,
            total: 0,
        }
    }

    /// Tell this module where to look for the input addr
    pub fn set_input_addr(&mut self, addr: *const u8) {
        self.input_addr = addr;
    }

    pub fn reset_input_addr(&mut self) {
        self.input_addr = core::ptr::null();
    }
}

impl<I, S> EmulatorModule<I, S> for RedirectStdinModule
where
    I: Unpin + HasLen + Debug,
    S: Unpin,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
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
        self.read = 0;
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
    I: Unpin + HasLen + Debug,
    S: Unpin,
{
    let h = emulator_modules.get_mut::<RedirectStdinModule>().unwrap();
    if h.input_addr.is_null() {
        return SyscallHookResult::new(None);
    }
    if syscall == SYS_read as i32 && x0 == 0 {
        /*
        println!(
            "Is sys read {:x} {} {:x} {:x} {} {} {} {} {}",
            rip, x0, x1, x2, x3, x4, x5, x6, x7
        );
        */
        let size = unsafe {
            let mut src = h.input_addr;
            src = src.wrapping_add(h.read);
            let dst = x1 as *mut u8;
            if h.total >= h.read {
                let size = std::cmp::min(x2, (h.total - h.read).try_into().unwrap());
                /*
                println!(
                    "trying to read {} bytes copying src: {:p} {:p} size: {} h.total: {} h.read {} ",
                    x2, src, dst, size, h.total, h.read
                );
                */
                dst.copy_from(src, size as usize);
                size
            } else {
                0
            }
        };
        // println!("copied {}", size);
        h.read += size as usize;
        return SyscallHookResult::new(Some(size));
    }
    SyscallHookResult::new(None)
}
