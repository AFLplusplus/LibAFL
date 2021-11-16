//! Sugar API to simplify the life of the naive user of `LibAFL`

pub mod inmemory;
pub use inmemory::InMemoryBytesCoverageSugar;

#[cfg(target_os = "linux")]
pub mod qemu;
#[cfg(target_os = "linux")]
pub use qemu::QemuBytesCoverageSugar;

#[cfg(target_family = "unix")]
pub mod forkserver;
#[cfg(target_family = "unix")]
pub use forkserver::ForkserverBytesCoverageSugar;

pub const DEFAULT_TIMEOUT_SECS: u64 = 1200;
pub const CORPUS_CACHE_SIZE: usize = 4096;

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
#[pyo3(name = "libafl_sugar")]
pub fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
    inmemory::pybind::register(py, m)?;
    #[cfg(target_os = "linux")]
    {
        qemu::pybind::register(py, m)?;
    }
    Ok(())
}
