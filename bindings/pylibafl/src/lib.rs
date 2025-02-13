use pyo3::prelude::*;

/// Setup python modules for `libafl_qemu` and `libafl_sugar`.
///
/// # Errors
/// Returns error if python libafl setup failed.
#[pymodule]
#[pyo3(name = "pylibafl")]
pub fn python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3_log::init();

    let modules = m.py().import("sys")?.getattr("modules")?;

    let sugar_module = PyModule::new(m.py(), "sugar")?;
    libafl_sugar::python_module(&sugar_module)?;
    m.add_submodule(&sugar_module)?;
    modules.set_item("pylibafl.sugar", sugar_module)?;

    #[cfg(target_os = "linux")]
    {
        let qemu_module = PyModule::new(m.py(), "qemu")?;
        libafl_qemu::python_module(&qemu_module)?;
        m.add_submodule(&qemu_module)?;
        modules.set_item("pylibafl.qemu", qemu_module)?;
    }

    let bolts_module = PyModule::new(m.py(), "libafl_bolts")?;
    libafl_bolts::pybind::python_module(&bolts_module)?;
    m.add_submodule(&bolts_module)?;
    modules.set_item("pylibafl.libafl_bolts", bolts_module)?;

    Ok(())
}
