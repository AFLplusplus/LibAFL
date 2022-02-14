use libafl;
use libafl_qemu;
use libafl_sugar;
use pyo3::prelude::*;

#[pymodule]
#[pyo3(name = "pylibafl")]
pub fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
    let sugar_module = PyModule::new(py, "sugar")?;
    libafl_sugar::python_module(py, sugar_module)?;
    m.add_submodule(sugar_module)?;

    let qemu_module = PyModule::new(py, "qemu")?;
    libafl_qemu::python_module(py, qemu_module)?;
    m.add_submodule(qemu_module)?;

    let libafl_module = PyModule::new(py, "libafl")?;
    libafl::python_module(py, libafl_module)?;
    m.add_submodule(libafl_module)?;

    Ok(())
}
