//! Welcome to `LibAFL` QEMU
//!
//! __Warning__: The documentation is built by default for `x86_64` in `usermode`. To access the documentation of other architectures or `systemmode`, the documentation must be rebuilt with the right features.
/*! */
#![doc = include_str!("../README.md")]
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
// libafl_qemu only supports Linux currently
#![cfg(target_os = "linux")]
// This lint triggers too often on the current GuestAddr type when emulating 64-bit targets because
// u64::from(GuestAddr) is a no-op, but the .into() call is needed when GuestAddr is u32.
#![cfg_attr(
    any(cpu_target = "x86_64", cpu_target = "aarch64"),
    allow(clippy::useless_conversion)
)]
// libafl_qemu_sys export types with empty struct markers (e.g. struct {} start_init_save)
// This causes bindgen to generate empty Rust struct that are generally not FFI-safe due to C++ having empty structs with size 1
// As the QEMU codebase is C, it is FFI-safe and we just ignore the warning
#![allow(improper_ctypes)]

use std::env;

pub use libafl_qemu_sys as sys;
pub use strum::IntoEnumIterator;

pub mod arch;
pub use arch::*;

pub mod elf;

pub mod modules;

pub mod executor;
pub use executor::QemuExecutor;
#[cfg(feature = "fork")]
pub use executor::QemuForkExecutor;

pub mod qemu;
pub use qemu::*;

pub mod emu;
pub use emu::*;

pub mod breakpoint;
pub mod command;
pub mod sync_exit;

pub use libafl_qemu_sys::{GuestAddr, MmapPerms};
#[cfg(feature = "systemmode")]
pub use libafl_qemu_sys::{GuestPhysAddr, GuestVirtAddr};

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
pub fn python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    use pyo3::types::PyString;

    let regsm = PyModule::new(m.py(), "regs")?;
    for r in Regs::iter() {
        let v: i32 = r.into();
        regsm.add(PyString::new(m.py(), &format!("{r:?}")), v)?;
    }
    m.add_submodule(&regsm)?;

    let mmapm = PyModule::new(m.py(), "mmap")?;
    for r in MmapPerms::iter() {
        let v: i32 = r.into();
        mmapm.add(PyString::new(m.py(), &format!("{r:?}")), v)?;
    }
    m.add_submodule(&mmapm)?;

    #[cfg(feature = "usermode")]
    m.add_class::<sys::MapInfo>()?;

    #[cfg(feature = "usermode")]
    m.add_class::<GuestMaps>()?;

    m.add_class::<SyscallHookResult>()?;
    m.add_class::<pybind::Qemu>()?;

    Ok(())
}
