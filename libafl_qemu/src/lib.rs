// libafl_qemu only supports Linux currently
#![cfg(target_os = "linux")]
// This lint triggers too often on the current GuestAddr type when emulating 64-bit targets because
// u64::from(GuestAddr) is a no-op, but the .into() call is needed when GuestAddr is u32.
#![cfg_attr(
    any(cpu_target = "x86_64", cpu_target = "aarch64"),
    allow(clippy::useless_conversion)
)]
#![allow(clippy::needless_pass_by_value)]

use std::env;

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

pub mod elf;

pub mod helper;
pub use helper::*;
pub mod hooks;
pub use hooks::*;

pub mod edges;
pub use edges::QemuEdgeCoverageHelper;
pub mod cmplog;
pub use cmplog::QemuCmpLogHelper;
pub mod snapshot;
pub use snapshot::QemuSnapshotHelper;
pub mod asan;
pub use asan::{init_with_asan, QemuAsanHelper};

pub mod executor;
pub use executor::{QemuExecutor, QemuForkExecutor};

pub mod emu;
pub use emu::*;

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
        regsm.add(&format!("{:?}", r), v)?;
    }
    m.add_submodule(regsm)?;

    let mmapm = PyModule::new(py, "mmap")?;
    for r in emu::MmapPerms::iter() {
        let v: i32 = r.into();
        mmapm.add(&format!("{:?}", r), v)?;
    }
    m.add_submodule(mmapm)?;

    m.add_class::<emu::MapInfo>()?;
    m.add_class::<emu::GuestMaps>()?;
    m.add_class::<emu::SyscallHookResult>()?;
    m.add_class::<emu::pybind::Emulator>()?;

    Ok(())
}
