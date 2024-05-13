/*!
`libafl_qemu_sys` is the crate exporting C symbols from QEMU.
Have a look at `libafl_qemu` for higher-level abstractions.

__Warning__: The documentation is built by default for `x86_64` in `usermode`. To access the documentation of other architectures or systemmode, the documentation must be rebuilt with the right features.
*/

#![forbid(unexpected_cfgs)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(unused_mut)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![cfg_attr(nightly, feature(used_with_arg))]

use num_enum::{IntoPrimitive, TryFromPrimitive};
use paste::paste;
use strum_macros::EnumIter;

#[cfg(all(not(feature = "clippy"), target_os = "linux"))]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
#[cfg(all(not(feature = "clippy"), target_os = "linux"))]
pub use bindings::*;

#[cfg(any(feature = "clippy", not(target_os = "linux")))]
#[rustfmt::skip]
mod x86_64_stub_bindings;

#[cfg(emulation_mode = "usermode")]
mod usermode;
#[cfg(emulation_mode = "usermode")]
pub use usermode::*;

#[cfg(emulation_mode = "systemmode")]
mod systemmode;
#[cfg(emulation_mode = "systemmode")]
pub use systemmode::*;

/// Safe linking with of extern "C" functions.
/// This macro makes sure the declared symbol is defined *at link time*, avoiding declaring non-existant symbols
/// that could be silently ignored during linking if unused.
///
/// This macro relies on a nightly feature, and can only be used in this mode
/// It is (nearly) a drop-in replacement for extern "C" { } blocks containing function and static declarations, and will have the same effect in practice.
#[macro_export]
macro_rules! extern_c_checked {
    () => {};

    ($visibility:vis fn $c_fn:ident($($param_ident:ident : $param_ty:ty),*) $( -> $ret_ty:ty )?; $($tail:tt)*) =>  {
        paste! {
            #[cfg_attr(nightly, used(linker))]
            static [<__ $c_fn:upper __>]: unsafe extern "C" fn($($param_ty),*) $( -> $ret_ty )? = $c_fn;
        }

        extern "C" {
            $visibility fn $c_fn($($param_ident : $param_ty),*) $( -> $ret_ty )?;
        }

        extern_c_checked!($($tail)*);
    };

    ($visibility:vis static $c_var:ident : $c_var_ty:ty; $($tail:tt)*) => {
        paste! {
            #[allow(non_camel_case_types)]
            #[allow(unused)]
            struct [<__ $c_var:upper _STRUCT__>] { member: *const $c_var_ty }

            unsafe impl Sync for [<__ $c_var:upper _STRUCT__>] {}

            #[cfg_attr(nightly, used(linker))]
            static [<__ $c_var:upper __>]: [<__ $c_var:upper _STRUCT__>] = unsafe { [<__ $c_var:upper _STRUCT__>] { member: core::ptr::addr_of!($c_var) } };
        }

        extern "C" {
            $visibility static $c_var: $c_var_ty;
        }

        extern_c_checked!($($tail)*);
    };

    ($visibility:vis static mut $c_var:ident : $c_var_ty:ty; $($tail:tt)*) => {
        paste! {
            #[allow(non_camel_case_types)]
            #[allow(unused)]
            struct [<__ $c_var:upper _STRUCT__>] { member: *const $c_var_ty }

            unsafe impl Sync for [<__ $c_var:upper _STRUCT__>] {}

            #[cfg_attr(nightly, used(linker))]
            static mut [<__ $c_var:upper __>]: [<__ $c_var:upper _STRUCT__>] = unsafe { [<__ $c_var:upper _STRUCT__>] { member: core::ptr::addr_of!($c_var) } };
        }

        extern "C" {
            $visibility static mut $c_var: $c_var_ty;
        }

        extern_c_checked!($($tail)*);
    };
}

#[cfg(target_os = "linux")]
use core::ops::BitAnd;
use std::ffi::c_void;

#[cfg(feature = "python")]
use pyo3::{pyclass, pymethods, IntoPy, PyObject, Python};
#[cfg(any(feature = "clippy", not(target_os = "linux")))]
pub use x86_64_stub_bindings::*;

pub type CPUStatePtr = *mut crate::CPUState;
pub type CPUArchStatePtr = *mut crate::CPUArchState;
pub type ExitReasonPtr = *mut crate::libafl_exit_reason;

pub type GuestUsize = crate::target_ulong;
pub type GuestIsize = crate::target_long;

pub type GuestAddr = crate::target_ulong;
pub type GuestPhysAddr = crate::hwaddr;
pub type GuestVirtAddr = crate::vaddr;

pub type GuestHwAddrInfo = crate::qemu_plugin_hwaddr;

#[derive(Debug)]
#[repr(C)]
#[cfg_attr(feature = "python", pyclass(unsendable))]
pub struct MapInfo {
    start: GuestAddr,
    end: GuestAddr,
    offset: GuestAddr,
    path: Option<String>,
    flags: i32,
    is_priv: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatPtr(pub *const c_void, pub *const c_void);

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter, PartialEq, Eq)]
#[repr(i32)]
pub enum MmapPerms {
    None = 0,
    Read = libc::PROT_READ,
    Write = libc::PROT_WRITE,
    Execute = libc::PROT_EXEC,
    ReadWrite = libc::PROT_READ | libc::PROT_WRITE,
    ReadExecute = libc::PROT_READ | libc::PROT_EXEC,
    WriteExecute = libc::PROT_WRITE | libc::PROT_EXEC,
    ReadWriteExecute = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
}

// from include/exec/memop.h

#[cfg(target_os = "linux")]
pub fn memop_size(op: MemOp) -> u32 {
    1 << op.bitand(MemOp_MO_SIZE).0
}

#[cfg(target_os = "linux")]
pub fn memop_big_endian(op: MemOp) -> bool {
    op.bitand(MemOp_MO_BSWAP) == MemOp_MO_BE
}

// from include/qemu/plugin.h

#[cfg(target_os = "linux")]
pub fn make_plugin_meminfo(oi: MemOpIdx, rw: qemu_plugin_mem_rw) -> qemu_plugin_meminfo_t {
    oi | (rw.0 << 16)
}

// from include/hw/core/cpu.h

#[cfg(target_os = "linux")]
pub fn cpu_env(cpu: *mut CPUState) -> *mut CPUArchState {
    unsafe { cpu.add(1) as *mut CPUArchState }
}

extern_c_checked! {
    //static libafl_page_size: GuestUsize;
    pub fn libafl_page_from_addr(addr: GuestAddr) -> GuestAddr;

    // CPUState* libafl_qemu_get_cpu(int cpu_index);
    pub fn libafl_qemu_get_cpu(cpu_index: i32) -> CPUStatePtr;
    // int libafl_qemu_num_cpus(void);
    pub fn libafl_qemu_num_cpus() -> i32;
    // CPUState* libafl_qemu_current_cpu(void);
    pub fn libafl_qemu_current_cpu() -> CPUStatePtr;

    // struct libafl_exit_reason* libafl_get_exit_reason(void);
    // fn libafl_get_exit_reason() -> ExitReasonPtr;

    pub fn libafl_qemu_cpu_index(cpu: CPUStatePtr) -> i32;

    pub fn libafl_qemu_write_reg(cpu: CPUStatePtr, reg: i32, val: *const u8) -> i32;
    pub fn libafl_qemu_read_reg(cpu: CPUStatePtr, reg: i32, val: *mut u8) -> i32;
    pub fn libafl_qemu_num_regs(cpu: CPUStatePtr) -> i32;

    // fn libafl_qemu_set_breakpoint(addr: u64) -> i32;
    // fn libafl_qemu_remove_breakpoint(addr: u64) -> i32;
    pub fn libafl_flush_jit();
    // fn libafl_qemu_trigger_breakpoint(cpu: CPUStatePtr);

    pub fn strlen(s: *const u8) -> usize;

    pub fn libafl_qemu_add_gdb_cmd(
        callback: extern "C" fn(*const (), *const u8, usize) -> i32,
        data: *const ()
    );
    pub fn libafl_qemu_gdb_reply(buf: *const u8, len: usize);
}

#[cfg_attr(feature = "python", pymethods)]
impl MapInfo {
    #[must_use]
    pub fn start(&self) -> GuestAddr {
        self.start
    }

    #[must_use]
    pub fn end(&self) -> GuestAddr {
        self.end
    }

    #[must_use]
    pub fn offset(&self) -> GuestAddr {
        self.offset
    }

    #[must_use]
    pub fn path(&self) -> Option<&String> {
        self.path.as_ref()
    }

    #[must_use]
    pub fn flags(&self) -> MmapPerms {
        MmapPerms::try_from(self.flags).unwrap()
    }

    #[must_use]
    pub fn is_priv(&self) -> bool {
        self.is_priv != 0
    }
}

impl MmapPerms {
    #[must_use]
    pub fn readable(&self) -> bool {
        matches!(
            self,
            MmapPerms::Read
                | MmapPerms::ReadWrite
                | MmapPerms::ReadExecute
                | MmapPerms::ReadWriteExecute
        )
    }

    #[must_use]
    pub fn writable(&self) -> bool {
        matches!(
            self,
            MmapPerms::Write
                | MmapPerms::ReadWrite
                | MmapPerms::WriteExecute
                | MmapPerms::ReadWriteExecute
        )
    }

    #[must_use]
    pub fn executable(&self) -> bool {
        matches!(
            self,
            MmapPerms::Execute
                | MmapPerms::ReadExecute
                | MmapPerms::WriteExecute
                | MmapPerms::ReadWriteExecute
        )
    }
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for MmapPerms {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}
