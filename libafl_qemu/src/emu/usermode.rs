use pyo3::{pymethods, PyObject, PyResult};
use pyo3::exceptions::PyValueError;
use libafl_qemu_sys::{GuestAddr, MmapPerms, VerifyAccess};

use crate::{
    emu::{HasExecutions, State},
    Emulator, EmulatorExitHandler, GuestMaps, HookData, NewThreadHookId, PostSyscallHookId,
    PreSyscallHookId, QemuHelperTuple, SyscallHookResult,
};

impl<QT, S, E> Emulator<QT, S, E>
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
    E: EmulatorExitHandler<QT, S>,
{
    /// This function gets the memory mappings from the emulator.
    #[must_use]
    pub fn mappings(&self) -> GuestMaps {
        self.qemu.mappings()
    }

    #[must_use]
    pub fn g2h<T>(&self, addr: GuestAddr) -> *mut T {
        self.qemu.g2h(addr)
    }

    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> GuestAddr {
        self.qemu.h2g(addr)
    }

    #[must_use]
    pub fn access_ok(&self, kind: VerifyAccess, addr: GuestAddr, size: usize) -> bool {
        self.qemu.access_ok(kind, addr, size)
    }

    pub fn force_dfl(&self) {
        self.qemu.force_dfl();
    }

    #[must_use]
    pub fn binary_path<'a>(&self) -> &'a str {
        self.qemu.binary_path()
    }

    #[must_use]
    pub fn load_addr(&self) -> GuestAddr {
        self.qemu.load_addr()
    }

    #[must_use]
    pub fn get_brk(&self) -> GuestAddr {
        self.qemu.get_brk()
    }

    pub fn set_brk(&self, brk: GuestAddr) {
        self.qemu.set_brk(brk);
    }

    #[must_use]
    pub fn get_mmap_start(&self) -> GuestAddr {
        self.qemu.get_mmap_start()
    }

    pub fn set_mmap_start(&self, start: GuestAddr) {
        self.qemu.set_mmap_start(start);
    }

    pub fn map_private(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.qemu.map_private(addr, size, perms)
    }

    pub fn map_fixed(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.qemu.map_fixed(addr, size, perms)
    }

    pub fn mprotect(&self, addr: GuestAddr, size: usize, perms: MmapPerms) -> Result<(), String> {
        self.qemu.mprotect(addr, size, perms)
    }

    pub fn unmap(&self, addr: GuestAddr, size: usize) -> Result<(), String> {
        self.qemu.unmap(addr, size)
    }

    #[allow(clippy::type_complexity)]
    pub fn add_pre_syscall_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(
            T,
            i32,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
        ) -> SyscallHookResult,
    ) -> PreSyscallHookId {
        self.qemu.add_pre_syscall_hook(data, callback)
    }

    #[allow(clippy::type_complexity)]
    pub fn add_post_syscall_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(
            T,
            GuestAddr,
            i32,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
            GuestAddr,
        ) -> GuestAddr,
    ) -> PostSyscallHookId {
        self.qemu.add_post_syscall_hook(data, callback)
    }

    pub fn add_new_thread_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, tid: u32) -> bool,
    ) -> NewThreadHookId {
        self.qemu.add_new_thread_hook(data, callback)
    }

    #[allow(clippy::type_complexity)]
    pub fn set_crash_hook(&self, callback: extern "C" fn(i32)) {
        self.qemu.set_crash_hook(callback);
    }
}

#[cfg(feature = "python")]
pub mod pybind {
    use pyo3::{pymethods, PyObject, PyResult, Python};
    use pyo3::exceptions::PyValueError;
    use pyo3::types::PyInt;
    use libafl_qemu_sys::{GuestAddr, MmapPerms};

    static mut PY_SYSCALL_HOOK: Option<PyObject> = None;

    extern "C" fn py_syscall_hook_wrapper(
        _data: u64,
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
        unsafe { PY_SYSCALL_HOOK.as_ref() }.map_or_else(
            || SyscallHookResult::new(None),
            |obj| {
                let args = (sys_num, a0, a1, a2, a3, a4, a5, a6, a7);
                Python::with_gil(|py| {
                    let ret = obj.call1(py, args).expect("Error in the syscall hook");
                    let any = ret.as_ref(py);
                    if any.is_none() {
                        SyscallHookResult::new(None)
                    } else {
                        let a: Result<&PyInt, _> = any.downcast();
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
            },
        )
    }

    #[pymethods]
    impl Qemu {
        fn g2h(&self, addr: GuestAddr) -> u64 {
            self.qemu.g2h::<*const u8>(addr) as u64
        }

        fn h2g(&self, addr: u64) -> GuestAddr {
            self.qemu.h2g(addr as *const u8)
        }

        fn binary_path(&self) -> String {
            self.qemu.binary_path().to_owned()
        }

        fn load_addr(&self) -> GuestAddr {
            self.qemu.load_addr()
        }

        fn map_private(&self, addr: GuestAddr, size: usize, perms: i32) -> PyResult<GuestAddr> {
            if let Ok(p) = MmapPerms::try_from(perms) {
                self.qemu
                    .map_private(addr, size, p)
                    .map_err(PyValueError::new_err)
            } else {
                Err(PyValueError::new_err("Invalid perms"))
            }
        }

        fn map_fixed(&self, addr: GuestAddr, size: usize, perms: i32) -> PyResult<GuestAddr> {
            if let Ok(p) = MmapPerms::try_from(perms) {
                self.qemu
                    .map_fixed(addr, size, p)
                    .map_err(PyValueError::new_err)
            } else {
                Err(PyValueError::new_err("Invalid perms"))
            }
        }

        fn mprotect(&self, addr: GuestAddr, size: usize, perms: i32) -> PyResult<()> {
            if let Ok(p) = MmapPerms::try_from(perms) {
                self.qemu
                    .mprotect(addr, size, p)
                    .map_err(PyValueError::new_err)
            } else {
                Err(PyValueError::new_err("Invalid perms"))
            }
        }

        fn unmap(&self, addr: GuestAddr, size: usize) -> PyResult<()> {
            self.qemu.unmap(addr, size).map_err(PyValueError::new_err)
        }

        fn set_syscall_hook(&self, hook: PyObject) {
            unsafe {
                crate::qemu::pybind::PY_SYSCALL_HOOK = Some(hook);
            }
            self.qemu
                .add_pre_syscall_hook(0u64, crate::qemu::pybind::py_syscall_hook_wrapper);
        }
    }
}
