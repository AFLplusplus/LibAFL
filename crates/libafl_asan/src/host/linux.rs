//! # linux
//! The `LinuxHost` supports the established means of interacting with the QEMU
//! emulator on Linux by means of issuing a bespoke syscall.
use syscalls::{
    Errno,
    raw::{syscall2, syscall3, syscall4},
};

use crate::{
    GuestAddr,
    host::{Host, HostAction},
    shadow::PoisonType,
};

#[derive(Debug)]
pub struct LinuxHost;

pub type LinuxHostResult<T> = Result<T, Errno>;

impl Host for LinuxHost {
    type Error = Errno;

    fn load(start: GuestAddr, len: usize) -> LinuxHostResult<()> {
        unsafe {
            Errno::from_ret(syscall3(
                Self::sysno(),
                HostAction::CheckLoad as usize,
                start,
                len,
            ))?;
        }
        Ok(())
    }

    fn store(start: GuestAddr, len: usize) -> LinuxHostResult<()> {
        unsafe {
            Errno::from_ret(syscall3(
                Self::sysno(),
                HostAction::CheckStore as usize,
                start,
                len,
            ))?;
        };
        Ok(())
    }

    fn poison(start: GuestAddr, len: usize, val: PoisonType) -> LinuxHostResult<()> {
        unsafe {
            Errno::from_ret(syscall4(
                Self::sysno(),
                HostAction::Poison as usize,
                start,
                len,
                val as usize,
            ))?;
        };
        Ok(())
    }

    fn unpoison(start: GuestAddr, len: usize) -> LinuxHostResult<()> {
        unsafe {
            Errno::from_ret(syscall3(
                Self::sysno(),
                HostAction::Unpoison as usize,
                start,
                len,
            ))?
        };
        Ok(())
    }

    fn is_poison(start: GuestAddr, len: usize) -> LinuxHostResult<bool> {
        unsafe {
            Ok(Errno::from_ret(syscall3(
                Self::sysno(),
                HostAction::IsPoison as usize,
                start,
                len,
            ))? != 0)
        }
    }

    fn swap(enabled: bool) -> LinuxHostResult<()> {
        unsafe {
            Errno::from_ret(syscall2(
                Self::sysno(),
                HostAction::SwapState as usize,
                enabled as usize,
            ))?;
        };
        Ok(())
    }

    fn track(start: GuestAddr, len: usize) -> LinuxHostResult<()> {
        unsafe {
            Errno::from_ret(syscall3(
                Self::sysno(),
                HostAction::Alloc as usize,
                start,
                len,
            ))?;
        };
        Ok(())
    }

    fn untrack(start: GuestAddr) -> LinuxHostResult<()> {
        unsafe { Errno::from_ret(syscall2(Self::sysno(), HostAction::Dealloc as usize, start))? };
        Ok(())
    }
}

impl LinuxHost {
    const SYSCALL_NO: usize = 0xa2a4;

    pub fn sysno() -> usize {
        Self::SYSCALL_NO
    }
}
