#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(unused_mut)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]

#[cfg(all(not(feature = "clippy"), target_os = "linux"))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(all(feature = "clippy", target_os = "linux"))]
mod x86_64_stub_bindings;

#[cfg(target_os = "linux")]
use core::ops::BitAnd;

#[cfg(all(feature = "clippy", target_os = "linux"))]
pub use x86_64_stub_bindings::*;

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
