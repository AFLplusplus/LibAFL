/*!
`libafl_qemu_sys` is the crate exporting C symbols from QEMU.
Have a look at `libafl_qemu` for higher-level abstractions.

__Warning__: The documentation is built by default for `x86_64` in `usermode`. To access the documentation of other architectures or systemmode, the documentation must be rebuilt with the right features.
*/

#![cfg_attr(nightly, feature(used_with_arg))]

use core::ffi::c_void;
#[cfg(target_os = "linux")]
use core::ops::BitAnd;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum_macros::EnumIter;

mod bindings;
pub use bindings::*;

#[cfg(feature = "usermode")]
mod usermode;
#[cfg(feature = "usermode")]
pub use usermode::*;

// #[cfg(feature = "systemmode")]
// mod systemmode;
// #[cfg(feature = "systemmode")]
// pub use systemmode::*;

/// Safe linking with of extern "C" functions.
///
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

        unsafe extern "C" {
            $visibility fn $c_fn($($param_ident : $param_ty),*) $( -> $ret_ty )?;
        }

        extern_c_checked!($($tail)*);
    };

    ($visibility:vis static $c_var:ident : $c_var_ty:ty; $($tail:tt)*) => {
        paste! {
            #[expect(non_camel_case_types)]
            #[expect(unused)]
            struct [<__ $c_var:upper _STRUCT__>] { member: *const $c_var_ty }

            unsafe impl Sync for [<__ $c_var:upper _STRUCT__>] {}

            #[cfg_attr(nightly, used(linker))]
            #[expect(unused_unsafe)]
            static [<__ $c_var:upper __>]: [<__ $c_var:upper _STRUCT__>] = unsafe { [<__ $c_var:upper _STRUCT__>] { member: &raw const $c_var } };
        }

        unsafe extern "C" {
            $visibility static $c_var: $c_var_ty;
        }

        extern_c_checked!($($tail)*);
    };

    ($visibility:vis static mut $c_var:ident : $c_var_ty:ty; $($tail:tt)*) => {
        paste! {
            #[expect(non_camel_case_types)]
            #[expect(unused)]
            struct [<__ $c_var:upper _STRUCT__>] { member: *const $c_var_ty }

            unsafe impl Sync for [<__ $c_var:upper _STRUCT__>] {}

            #[cfg_attr(nightly, used(linker))]
            #[expect(unused_unsafe)]
            static mut [<__ $c_var:upper __>]: [<__ $c_var:upper _STRUCT__>] = unsafe { [<__ $c_var:upper _STRUCT__>] { member: &raw const $c_var } };
        }

        unsafe extern "C" {
            $visibility static mut $c_var: $c_var_ty;
        }

        extern_c_checked!($($tail)*);
    };
}

pub type CPUStatePtr = *mut CPUState;
pub type CPUArchStatePtr = *mut CPUArchState;
pub type ExitReasonPtr = *mut libafl_exit_reason;

pub type GuestUsize = target_ulong;
pub type GuestIsize = target_long;

pub type GuestAddr = target_ulong;
pub type GuestPhysAddr = hwaddr;
pub type GuestVirtAddr = vaddr;

pub type GuestHwAddrInfo = qemu_plugin_hwaddr;

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
#[must_use]
pub fn memop_size(op: MemOp) -> u32 {
    1 << op.bitand(MemOp_MO_SIZE).0
}

#[cfg(target_os = "linux")]
#[must_use]
pub fn memop_big_endian(op: MemOp) -> bool {
    op.bitand(MemOp_MO_BSWAP) == MemOp_MO_BE
}

// from include/qemu/plugin.h

#[cfg(target_os = "linux")]
#[must_use]
pub fn make_plugin_meminfo(oi: MemOpIdx, rw: qemu_plugin_mem_rw) -> qemu_plugin_meminfo_t {
    oi | (rw.0 << 16)
}

// from include/hw/core/cpu.h

/// # Safety
/// Will dereference the `cpu` pointer.
#[cfg(target_os = "linux")]
pub unsafe fn cpu_env(cpu: *mut CPUState) -> *mut CPUArchState {
    unsafe { cpu.add(1) as *mut CPUArchState }
}
