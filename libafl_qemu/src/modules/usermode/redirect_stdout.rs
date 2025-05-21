use core::{
    fmt::{self, Debug},
    slice::from_raw_parts,
};

use libafl_bolts::HasLen;
use libafl_qemu_sys::GuestAddr;

#[cfg(not(cpu_target = "hexagon"))]
use crate::SYS_write;
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
const SYS_write: u8 = 64;

/// This module hijacks any read to buffer from stdin, and instead fill the buffer from the specified input address
/// This is useful when your binary target reads the input from the stdin.
/// With this you can just fuzz more like afl++
/// You need to use this with snapshot module!
#[derive(Clone)]
pub struct RedirectStdoutModule<F>
where
    F: FnMut(&[u8]),
{
    stdout: Option<F>,
    stderr: Option<F>,
}

impl<F> Debug for RedirectStdoutModule<F>
where
    F: FnMut(&[u8]),
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectStdoutModule")
            .finish_non_exhaustive()
    }
}

impl<F> Default for RedirectStdoutModule<F>
where
    F: FnMut(&[u8]),
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F> RedirectStdoutModule<F>
where
    F: FnMut(&[u8]),
{
    #[must_use]
    /// constuctor
    pub fn new() -> Self {
        Self {
            stdout: None,
            stderr: None,
        }
    }
}

impl<F> RedirectStdoutModule<F>
where
    F: FnMut(&[u8]) + Clone,
{
    #[must_use]
    /// Create with specified stdout callback
    pub fn with_stdout(&self, stdout: F) -> Self {
        Self {
            stdout: Some(stdout),
            stderr: self.stderr.clone(),
        }
    }

    #[must_use]
    /// Create with specified stderr callback
    pub fn with_stderr(&self, stderr: F) -> Self {
        Self {
            stdout: self.stdout.clone(),
            stderr: Some(stderr),
        }
    }
}

impl<F, I, S> EmulatorModule<I, S> for RedirectStdoutModule<F>
where
    I: Unpin + HasLen + Debug,
    S: Unpin,
    F: FnMut(&[u8]) + 'static,
{
    fn first_exec<ET>(
        &mut self,
        _qemu: Qemu,
        emulator_modules: &mut EmulatorModules<ET, I, S>,
        _state: &mut S,
    ) where
        ET: EmulatorModuleTuple<I, S>,
    {
        emulator_modules.pre_syscalls(Hook::Function(syscall_write_hook::<F, ET, I, S>));
    }
}

#[expect(clippy::too_many_arguments)]
fn syscall_write_hook<F, ET, I, S>(
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
    F: FnMut(&[u8]) + 'static,
{
    let h = emulator_modules
        .get_mut::<RedirectStdoutModule<F>>()
        .unwrap();
    if syscall != SYS_write as i32 {
        return SyscallHookResult::Run;
    }

    let fd = x0 as i32;
    let buf = x1 as *const u8;
    let len = x2;

    let callback = match fd {
        libc::STDOUT_FILENO => h.stdout.as_mut(),
        libc::STDERR_FILENO => h.stderr.as_mut(),
        _ => return SyscallHookResult::Run,
    };

    if let Some(callback) = callback {
        let buf = unsafe { from_raw_parts(buf, len as usize) };
        (callback)(buf);
    }

    SyscallHookResult::Skip(len)
}
