use core::fmt::Debug;

use libafl::inputs::TargetBytesConverter;
use libafl_bolts::{AsSlice, HasLen};
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
const SYS_eSYS_readxecve: u8 = 63;

/// This module hijacks any read to buffer from stdin, and instead fill the buffer from the specified input address
/// This is useful when your binary target reads the input from the stdin.
/// With this you can just fuzz more like afl++
/// You need to use this with snapshot module!
#[derive(Debug)]
pub struct RedirectStdinModule<TC> {
    bytes_converter: TC,
    input_addr: *const u8,
    read: usize,
    total: usize,
}

impl<TC> RedirectStdinModule<TC> {
    #[must_use]
    /// constuctor
    pub fn new(bytes_converter: TC) -> Self {
        Self {
            bytes_converter,
            input_addr: core::ptr::null(),
            read: 0,
            total: 0,
        }
    }
}

impl<I, S, TC> EmulatorModule<I, S> for RedirectStdinModule<TC>
where
    I: Unpin + HasLen + Debug,
    S: Unpin,
    TC: 'static + TargetBytesConverter<I> + Debug,
{
    fn post_qemu_init<ET>(&mut self, _qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.pre_syscalls(Hook::Function(syscall_read_hook::<ET, I, S, TC>));
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
        let target_bytes = self.bytes_converter.to_target_bytes(input);
        let buf = target_bytes.as_slice();
        self.input_addr = buf.as_ptr() as *const u8;
        self.total = input.len();
        self.read = 0;
    }
}

#[expect(clippy::too_many_arguments)]
fn syscall_read_hook<ET, I, S, TC>(
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
    TC: 'static + TargetBytesConverter<I> + Debug,
{
    let h = emulator_modules
        .get_mut::<RedirectStdinModule<TC>>()
        .unwrap();
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
            src = src.wrapping_add(h.read);
            let dst = x1 as *mut u8;
            if h.total >= h.read {
                let size = std::cmp::min(x2, (h.total - h.read).try_into().unwrap());
                println!(
                    "trying to read {} copying {:p} {:p} size: {} h.total: {} h.read {} ",
                    x2, src, dst, size, h.total, h.read
                );
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
