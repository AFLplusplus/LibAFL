#![cfg_attr(nightly, feature(used_with_arg))]
//! Welcome to `LibAFL` QEMU
//!
//! __Warning__: The documentation is built by default for `x86_64` in `usermode`. To access the documentation of other architectures or `systemmode`, the documentation must be rebuilt with the right features.
#![doc = include_str!("../../README.md")]
/*! */
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
// libafl_qemu only supports Linux currently
#![cfg(target_os = "linux")]
// This lint triggers too often on the current GuestAddr type when emulating 64-bit targets because
// u64::from(GuestAddr) is a no-op, but the .into() call is needed when GuestAddr is u32.
#![cfg_attr(
    any(cpu_target = "x86_64", cpu_target = "aarch64"),
    allow(clippy::useless_conversion)
)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::needless_pass_by_ref_mut)]
#![allow(clippy::transmute_ptr_to_ptr)]
#![allow(clippy::ptr_cast_constness)]
#![allow(clippy::too_many_arguments)]
// Till they fix this buggy lint in clippy
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::borrow_deref_ref)]
// Allow only ATM, it will be evetually removed
#![allow(clippy::missing_safety_doc)]
// libafl_qemu_sys export types with empty struct markers (e.g. struct {} start_init_save)
// This causes bindgen to generate empty Rust struct that are generally not FFI-safe due to C++ having empty structs with size 1
// As the QEMU codebase is C, it is FFI-safe and we just ignore the warning
#![allow(improper_ctypes)]

use std::env;

pub use libafl_qemu_sys as sys;
pub use strum::IntoEnumIterator;

#[cfg(cpu_target = "aarch64")]
pub mod aarch64;
#[cfg(all(cpu_target = "aarch64", not(feature = "clippy")))]
pub use aarch64::*;

#[cfg(cpu_target = "arm")]
pub mod arm;
#[cfg(all(cpu_target = "arm", not(feature = "clippy")))]
pub use arm::*;

#[cfg(cpu_target = "i386")]
pub mod i386;
#[cfg(all(cpu_target = "i386", not(feature = "clippy")))]
pub use i386::*;

#[cfg(cpu_target = "x86_64")]
pub mod x86_64;
#[cfg(cpu_target = "x86_64")]
pub use x86_64::*;

#[cfg(cpu_target = "mips")]
pub mod mips;
#[cfg(cpu_target = "mips")]
pub use mips::*;

#[cfg(cpu_target = "ppc")]
pub mod ppc;
#[cfg(cpu_target = "ppc")]
pub use ppc::*;

#[cfg(cpu_target = "hexagon")]
pub mod hexagon;
#[cfg(cpu_target = "hexagon")]
pub use hexagon::*;

pub mod elf;

pub mod helper;
pub use helper::*;
pub mod hooks;
pub use hooks::*;

pub mod edges;
pub use edges::QemuEdgeCoverageHelper;

#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub mod cmplog;
#[cfg(not(any(cpu_target = "mips", cpu_target = "hexagon")))]
pub use cmplog::QemuCmpLogHelper;

#[cfg(all(emulation_mode = "usermode", feature = "injections"))]
pub mod injections;
#[cfg(all(emulation_mode = "usermode", feature = "injections"))]
pub use injections::QemuInjectionHelper;

#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub mod snapshot;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use snapshot::QemuSnapshotHelper;

#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub mod asan;
#[cfg(all(emulation_mode = "usermode", not(cpu_target = "hexagon")))]
pub use asan::{init_with_asan, QemuAsanHelper};

#[cfg(not(cpu_target = "hexagon"))]
pub mod calls;
#[cfg(not(cpu_target = "hexagon"))]
pub mod drcov;

pub mod executor;
pub use executor::QemuExecutor;
#[cfg(feature = "fork")]
pub use executor::QemuForkExecutor;

pub mod emu;
pub use emu::*;

pub mod sync_backdoor;

#[must_use]
pub fn filter_qemu_args() -> Vec<String> {
    let mut args = vec![env::args().next().unwrap()];
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

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
#[pyo3(name = "libafl_qemu")]
#[allow(clippy::items_after_statements, clippy::too_many_lines)]
pub fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
    let regsm = PyModule::new(py, "regs")?;
    for r in Regs::iter() {
        let v: i32 = r.into();
        regsm.add(&format!("{r:?}"), v)?;
    }
    m.add_submodule(regsm)?;

    let mmapm = PyModule::new(py, "mmap")?;
    for r in emu::MmapPerms::iter() {
        let v: i32 = r.into();
        mmapm.add(&format!("{r:?}"), v)?;
    }
    m.add_submodule(mmapm)?;

    m.add_class::<emu::MapInfo>()?;
    m.add_class::<emu::GuestMaps>()?;
    m.add_class::<emu::SyscallHookResult>()?;
    m.add_class::<emu::pybind::Emulator>()?;

    Ok(())
}
