//! Sugar API to simplify the life of the naibe user of `LibAFL`

pub mod inmemory;
pub use inmemory::InMemoryBytesCoverageSugar;

#[cfg(target_os = "linux")]
pub mod qemu;
#[cfg(target_os = "linux")]
pub use qemu::QemuBytesCoverageSugar;

pub const DEFAULT_TIMEOUT_SECS: u64 = 1200;
pub const CORPUS_CACHE_SIZE: usize = 4096;

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
#[pyo3(name = "libafl_sugar")]
fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
    inmemory::pybind::register(py, m)?;
    Ok(())
}
