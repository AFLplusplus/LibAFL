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

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
#[pyo3(name = "libafl_qemu")]
fn python_module(_py: Python, m: &PyModule) -> PyResult<()> {
    use pyo3::exceptions::PyValueError;
    use core::mem::transmute;

    #[pyfn(m)]
    fn init(args: Vec<String>, env: Vec<(String, String)>) -> i32 {
        emu::init(&args, &env)
    }

    #[pyfn(m)]
    fn write_mem(addr: u64, buf: &[u8]) {
        emu::write_mem(addr, buf)
    }
    #[pyfn(m)]
    fn read_mem(addr: u64, size: usize) -> Vec<u8> {
        let mut buf = vec![];
        unsafe { buf.set_len(size) };
        emu::read_mem(addr, &mut buf);
        buf
    }
    #[pyfn(m)]
    fn num_regs() -> i32 {
        emu::num_regs()
    }
    #[pyfn(m)]
    fn write_reg(reg: i32, val: u64) -> PyResult<()> {
        emu::write_reg(reg, val).map_err(|e| PyValueError::new_err(e))
    }
    #[pyfn(m)]
    fn read_reg(reg: i32) -> PyResult<u64> {
        emu::read_reg(reg).map_err(|e| PyValueError::new_err(e))
    }
    #[pyfn(m)]
    fn set_breakpoint(addr: u64) {
        emu::set_breakpoint(addr)
    }
    #[pyfn(m)]
    fn remove_breakpoint(addr: u64) {
        emu::remove_breakpoint(addr)
    }
    #[pyfn(m)]
    fn run() {
        emu::run()
    }
    #[pyfn(m)]
    fn g2h(addr: u64) -> u64 {
        unsafe { transmute(emu::g2h::<*const u8>(addr)) }
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
    Ok(())
}
