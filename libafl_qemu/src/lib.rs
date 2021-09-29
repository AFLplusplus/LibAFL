use std::env;

pub mod amd64;
pub mod x86;

pub mod elf;
pub mod hooks;

#[cfg(target_os = "linux")]
pub mod executor;
#[cfg(target_os = "linux")]
pub use executor::QemuExecutor;

#[cfg(target_os = "linux")]
pub mod emu;
#[cfg(target_os = "linux")]
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

#[cfg(all(target_os = "linux", feature = "python"))]
use pyo3::{prelude::*, types::PyInt};

#[cfg(all(target_os = "linux", feature = "python"))]
static mut PY_SYSCALL_HOOK: Option<PyObject> = None;

#[cfg(all(target_os = "linux", feature = "python"))]
#[pymodule]
#[pyo3(name = "libafl_qemu")]
#[allow(clippy::items_after_statements)]
pub fn python_module(py: Python, m: &PyModule) -> PyResult<()> {
    use core::mem::transmute;
    use pyo3::exceptions::PyValueError;
    use std::convert::TryFrom;
    use strum::IntoEnumIterator;

    #[pyfn(m)]
    #[allow(clippy::needless_pass_by_value)]
    fn init(args: Vec<String>, env: Vec<(String, String)>) -> i32 {
        emu::init(&args, &env)
    }

    #[pyfn(m)]
    #[allow(clippy::needless_pass_by_value)]
    fn write_mem(addr: u64, buf: &[u8]) {
        emu::write_mem(addr, buf);
    }
    #[pyfn(m)]
    fn read_mem(addr: u64, size: usize) -> Vec<u8> {
        let mut buf = vec![0; size];
        emu::read_mem(addr, &mut buf);
        buf
    }
    #[pyfn(m)]
    fn num_regs() -> i32 {
        emu::num_regs()
    }
    #[pyfn(m)]
    fn write_reg(reg: i32, val: u64) -> PyResult<()> {
        emu::write_reg(reg, val).map_err(PyValueError::new_err)
    }
    #[pyfn(m)]
    fn read_reg(reg: i32) -> PyResult<u64> {
        emu::read_reg(reg).map_err(PyValueError::new_err)
    }
    #[pyfn(m)]
    fn set_breakpoint(addr: u64) {
        emu::set_breakpoint(addr);
    }
    #[pyfn(m)]
    fn remove_breakpoint(addr: u64) {
        emu::remove_breakpoint(addr);
    }
    #[pyfn(m)]
    fn run() {
        emu::run();
    }
    #[pyfn(m)]
    fn g2h(addr: u64) -> u64 {
        emu::g2h::<*const u8>(addr) as u64
    }
    #[pyfn(m)]
    fn h2g(addr: u64) -> u64 {
        emu::h2g(unsafe { transmute::<_, *const u8>(addr) })
    }
    #[pyfn(m)]
    fn binary_path() -> String {
        emu::binary_path().to_owned()
    }
    #[pyfn(m)]
    fn load_addr() -> u64 {
        emu::load_addr()
    }
    #[pyfn(m)]
    fn map_private(addr: u64, size: usize, perms: i32) -> PyResult<u64> {
        if let Ok(p) = MmapPerms::try_from(perms) {
            emu::map_private(addr, size, p).map_err(PyValueError::new_err)
        } else {
            Err(PyValueError::new_err("Invalid perms"))
        }
    }

    extern "C" fn py_syscall_hook_wrapper(
        sys_num: i32,
        a0: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
        a6: u64,
        a7: u64,
    ) -> SyscallHookResult {
        if let Some(obj) = unsafe { &PY_SYSCALL_HOOK } {
            let args = (sys_num, a0, a1, a2, a3, a4, a5, a6, a7);
            Python::with_gil(|py| {
                let ret = obj.call1(py, args).expect("Error in the syscall hook");
                let any = ret.as_ref(py);
                if any.is_none() {
                    SyscallHookResult::new(None)
                } else {
                    let a: Result<&PyInt, _> = any.try_into();
                    if let Ok(i) = a {
                        SyscallHookResult::new(Some(
                            i.extract().expect("Invalid syscall hook return value"),
                        ))
                    } else {
                        SyscallHookResult::extract(any)
                            .expect("The syscall hook must return a SyscallHookResult")
                    }
                }
            })
        } else {
            SyscallHookResult::new(None)
        }
    }
    #[pyfn(m)]
    fn set_syscall_hook(hook: PyObject) {
        unsafe {
            PY_SYSCALL_HOOK = Some(hook);
        }
        emu::set_syscall_hook(py_syscall_hook_wrapper);
    }

    let child_module = PyModule::new(py, "x86")?;
    for r in x86::X86Regs::iter() {
        let v: i32 = r.into();
        child_module.add(&format!("{:?}", r), v)?;
    }
    m.add_submodule(child_module)?;

    let child_module = PyModule::new(py, "amd64")?;
    for r in amd64::Amd64Regs::iter() {
        let v: i32 = r.into();
        child_module.add(&format!("{:?}", r), v)?;
    }
    m.add_submodule(child_module)?;

    let child_module = PyModule::new(py, "mmap")?;
    for r in emu::MmapPerms::iter() {
        let v: i32 = r.into();
        child_module.add(&format!("{:?}", r), v)?;
    }
    m.add_submodule(child_module)?;

    m.add_class::<emu::MapInfo>()?;
    m.add_class::<emu::GuestMaps>()?;
    m.add_class::<emu::SyscallHookResult>()?;

    Ok(())
}
