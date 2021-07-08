//! Expose QEMU user LibAFL C api to Rust

use core::{convert::Into, mem::transmute, ptr::copy_nonoverlapping};
use libc;
use num::Num;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::{env, mem::size_of, slice::from_raw_parts, str::from_utf8_unchecked};

pub mod amd64;
pub mod x86;

pub mod elf;

pub const SKIP_EXEC_HOOK: u32 = u32::MAX;

extern "C" {
    fn libafl_qemu_write_reg(reg: i32, val: *const u8) -> i32;
    fn libafl_qemu_read_reg(reg: i32, val: *mut u8) -> i32;
    fn libafl_qemu_num_regs() -> i32;
    fn libafl_qemu_set_breakpoint(addr: u64) -> i32;
    fn libafl_qemu_remove_breakpoint(addr: u64) -> i32;
    fn libafl_qemu_run() -> i32;

    fn strlen(s: *const u8) -> usize;

    /// abi_long target_mmap(abi_ulong start, abi_ulong len, int target_prot, int flags, int fd, abi_ulong offset)
    fn target_mmap(start: u64, len: u64, target_prot: i32, flags: i32, fd: i32, offset: u64)
        -> u64;

    /// int target_munmap(abi_ulong start, abi_ulong len)
    fn target_munmap(start: u64, len: u64) -> i32;
    
    static exec_path: *const u8;
    static guest_base: isize;
    
    static mut libafl_exec_edge_hook: unsafe extern "C" fn(u32);
    static mut libafl_gen_edge_hook: unsafe extern "C" fn(u64, u64) -> u32;
    static mut libafl_exec_block_hook: unsafe extern "C" fn(u64);
    static mut libafl_gen_block_hook: unsafe extern "C" fn(u64) -> u32;
}

#[derive(IntoPrimitive, TryFromPrimitive, Clone, Copy)]
#[repr(i32)]
#[allow(clippy::pub_enum_variant_names)]
pub enum MmapPerms {
    Read = libc::PROT_READ,
    Write = libc::PROT_WRITE,
    Execute = libc::PROT_EXEC,
    ReadWrite = libc::PROT_READ | libc::PROT_WRITE,
    ReadExecute = libc::PROT_READ | libc::PROT_EXEC,
    WriteExecute = libc::PROT_WRITE | libc::PROT_EXEC,
    ReadWriteExecute = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
}

pub struct QemuEmulator {}

impl QemuEmulator {
    pub fn write_mem<T>(&mut self, addr: u64, buf: &[T]) {
        let host_addr = self.g2h(addr);
        unsafe {
            copy_nonoverlapping(
                buf.as_ptr() as *const _ as *const u8,
                host_addr,
                buf.len() * size_of::<T>(),
            )
        }
    }

    pub fn read_mem<T>(&mut self, addr: u64, buf: &mut [T]) {
        let host_addr = self.g2h(addr);
        unsafe {
            copy_nonoverlapping(
                host_addr as *const u8,
                buf.as_mut_ptr() as *mut _ as *mut u8,
                buf.len() * size_of::<T>(),
            )
        }
    }

    pub fn num_regs(&self) -> i32 {
        unsafe { libafl_qemu_num_regs() }
    }

    pub fn write_reg<R, T>(&mut self, reg: R, val: T) -> Result<(), String>
    where
        T: Num + PartialOrd + Copy,
        R: Into<i32>,
    {
        let reg = reg.into();
        let success = unsafe { libafl_qemu_write_reg(reg, &val as *const _ as *const u8) };
        if success != 0 {
            Ok(())
        } else {
            Err(format!("Failed to write to register {}", reg))
        }
    }

    pub fn read_reg<R, T>(&mut self, reg: R) -> Result<T, String>
    where
        T: Num + PartialOrd + Copy,
        R: Into<i32>,
    {
        let reg = reg.into();
        let mut val = T::zero();
        let success = unsafe { libafl_qemu_read_reg(reg, &mut val as *mut _ as *mut u8) };
        if success != 0 {
            Ok(val)
        } else {
            Err(format!("Failed to read register {}", reg))
        }
    }

    pub fn set_breakpoint(&mut self, addr: u64) {
        unsafe { libafl_qemu_set_breakpoint(addr) };
    }

    pub fn remove_breakpoint(&mut self, addr: u64) {
        unsafe { libafl_qemu_remove_breakpoint(addr) };
    }

    pub fn run(&mut self) {
        unsafe { libafl_qemu_run() };
    }

    pub fn g2h(&self, addr: u64) -> *mut u8 {
        unsafe { transmute(addr as isize + guest_base) }
    }

    pub fn h2g(&self, addr: *const u8) -> u64 {
        unsafe { (transmute::<_, isize>(addr) - guest_base) as u64 }
    }

    pub fn exec_path(&self) -> &str {
        unsafe { from_utf8_unchecked(from_raw_parts(exec_path, strlen(exec_path))) }
    }

    pub fn map_private(&mut self, addr: u64, size: usize, perms: MmapPerms) -> Result<u64, String> {
        let res = unsafe {
            target_mmap(
                addr,
                size as u64,
                perms.into(),
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if res != 0 {
            Ok(res)
        } else {
            Err(format!("Failed to map {}", addr))
        }
    }

    pub fn unmap(&mut self, addr: u64, size: usize) -> Result<(), String> {
        if unsafe { target_munmap(addr, size as u64) } == 0 {
            Ok(())
        } else {
            Err(format!("Failed to unmap {}", addr))
        }
    }
    
    pub fn set_exec_edge_hook(&mut self, hook: extern "C" fn(u32)) {
        unsafe { libafl_exec_edge_hook = hook };
    }
    
    pub fn set_gen_edge_hook(&mut self, hook: extern "C" fn(u64, u64) -> u32) {
        unsafe { libafl_gen_edge_hook = hook };
    }

    pub fn set_exec_block_hook(&mut self, hook: extern "C" fn(u64)) {
        unsafe { libafl_exec_block_hook = hook };
    }
    
    pub fn set_gen_block_hook(&mut self, hook: extern "C" fn(u64) -> u32) {
        unsafe { libafl_gen_block_hook = hook };
    }

    pub fn new() -> Self {
        Self {}
    }
}

pub fn filter_qemu_args() -> Vec<String> {
    let mut args = vec![env::args().nth(0).unwrap()];
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
