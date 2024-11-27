use std::{
    intrinsics::copy_nonoverlapping, mem::MaybeUninit, slice::from_raw_parts_mut,
    str::from_utf8_unchecked_mut,
};

use libafl_qemu_sys::{
    exec_path, free_self_maps, guest_base, libafl_force_dfl, libafl_get_brk, libafl_load_addr,
    libafl_maps_first, libafl_maps_next, libafl_qemu_run, libafl_set_brk, mmap_next_start,
    pageflags_get_root, read_self_maps, GuestAddr, GuestUsize, IntervalTreeNode, IntervalTreeRoot,
    MapInfo, MmapPerms, VerifyAccess,
};
use libc::{c_int, c_uchar, strlen};
#[cfg(feature = "python")]
use pyo3::{pyclass, pymethods, IntoPyObject, Py, PyRef, PyRefMut, Python};

use crate::{Qemu, CPU};

#[cfg_attr(feature = "python", pyclass(unsendable))]
pub struct GuestMaps {
    self_maps_root: *mut IntervalTreeRoot,
    pageflags_node: *mut IntervalTreeNode,
}

// Consider a private new only for Emulator
impl GuestMaps {
    #[must_use]
    pub(crate) fn new() -> Self {
        unsafe {
            let pageflags_root = pageflags_get_root();
            let self_maps_root = read_self_maps();
            let pageflags_first = libafl_maps_first(pageflags_root);
            Self {
                self_maps_root,
                pageflags_node: pageflags_first,
            }
        }
    }
}

impl Iterator for GuestMaps {
    type Item = MapInfo;

    #[allow(clippy::uninit_assumed_init)]
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut ret = MaybeUninit::uninit();

            self.pageflags_node =
                libafl_maps_next(self.pageflags_node, self.self_maps_root, ret.as_mut_ptr());

            let ret = ret.assume_init();

            if ret.is_valid {
                Some(ret.into())
            } else {
                None
            }
        }
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl GuestMaps {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }

    fn __next__(mut slf: PyRefMut<Self>) -> Option<Py<MapInfo>> {
        Python::with_gil(|py| slf.next().map(|x| x.into_pyobject(py).unwrap().into()))
    }
}

impl Drop for GuestMaps {
    fn drop(&mut self) {
        unsafe {
            free_self_maps(self.self_maps_root);
        }
    }
}

impl CPU {
    /// Read a value from a guest address.
    /// The input address is not checked for validity.
    ///
    /// # Safety
    /// This will read from a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn read_mem_unchecked(&self, addr: GuestAddr, buf: &mut [u8]) {
        let host_addr = Qemu::get().unwrap().g2h(addr);
        copy_nonoverlapping(host_addr, buf.as_mut_ptr(), buf.len());
    }

    /// Write a value to a guest address.
    /// The input address in not checked for validity.
    ///
    /// # Safety
    /// This will write to a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn write_mem_unchecked(&self, addr: GuestAddr, buf: &[u8]) {
        let host_addr = Qemu::get().unwrap().g2h(addr);
        copy_nonoverlapping(buf.as_ptr(), host_addr, buf.len());
    }

    #[must_use]
    pub fn g2h<T>(&self, addr: GuestAddr) -> *mut T {
        unsafe { (addr as usize + guest_base) as *mut T }
    }

    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> GuestAddr {
        unsafe { (addr as usize - guest_base) as GuestAddr }
    }

    #[must_use]
    pub fn access_ok(&self, kind: VerifyAccess, addr: GuestAddr, size: usize) -> bool {
        unsafe {
            // TODO add support for tagged GuestAddr
            libafl_qemu_sys::page_check_range(addr, size as GuestAddr, kind.into())
        }
    }
}

#[allow(clippy::unused_self)]
impl Qemu {
    #[must_use]
    pub fn mappings(&self) -> GuestMaps {
        GuestMaps::new()
    }

    #[must_use]
    pub fn g2h<T>(&self, addr: GuestAddr) -> *mut T {
        unsafe { (addr as usize + guest_base) as *mut T }
    }

    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> GuestAddr {
        unsafe { (addr as usize - guest_base) as GuestAddr }
    }

    #[must_use]
    pub fn access_ok(&self, kind: VerifyAccess, addr: GuestAddr, size: usize) -> bool {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .access_ok(kind, addr, size)
    }

    pub fn force_dfl(&self) {
        unsafe {
            libafl_force_dfl = 1;
        }
    }

    pub(super) unsafe fn run_inner(self) {
        libafl_qemu_run();
    }

    #[must_use]
    pub fn binary_path<'a>(&self) -> &'a str {
        unsafe {
            from_utf8_unchecked_mut(from_raw_parts_mut(
                exec_path as *mut c_uchar,
                strlen(exec_path.cast_const()),
            ))
        }
    }

    #[must_use]
    pub fn load_addr(&self) -> GuestAddr {
        unsafe { libafl_load_addr() as GuestAddr }
    }

    #[must_use]
    pub fn get_brk(&self) -> GuestAddr {
        unsafe { libafl_get_brk() as GuestAddr }
    }

    pub fn set_brk(&self, brk: GuestAddr) {
        unsafe { libafl_set_brk(brk.into()) };
    }

    #[must_use]
    pub fn get_mmap_start(&self) -> GuestAddr {
        unsafe { mmap_next_start }
    }

    pub fn set_mmap_start(&self, start: GuestAddr) {
        unsafe { mmap_next_start = start };
    }

    #[allow(clippy::cast_sign_loss)]
    fn mmap(
        self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
        flags: c_int,
    ) -> Result<GuestAddr, ()> {
        let res = unsafe {
            libafl_qemu_sys::target_mmap(addr, size as GuestUsize, perms.into(), flags, -1, 0)
        };
        if res <= 0 {
            Err(())
        } else {
            Ok(res as GuestAddr)
        }
    }

    pub fn map_private(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.mmap(addr, size, perms, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS)
            .map_err(|()| format!("Failed to map {addr}"))
            .map(|addr| addr as GuestAddr)
    }

    pub fn map_fixed(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.mmap(
            addr,
            size,
            perms,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        )
        .map_err(|()| format!("Failed to map {addr}"))
        .map(|addr| addr as GuestAddr)
    }

    pub fn mprotect(&self, addr: GuestAddr, size: usize, perms: MmapPerms) -> Result<(), String> {
        let res = unsafe {
            libafl_qemu_sys::target_mprotect(addr.into(), size as GuestUsize, perms.into())
        };
        if res == 0 {
            Ok(())
        } else {
            Err(format!("Failed to mprotect {addr}"))
        }
    }

    pub fn unmap(&self, addr: GuestAddr, size: usize) -> Result<(), String> {
        if unsafe { libafl_qemu_sys::target_munmap(addr.into(), size as GuestUsize) } == 0 {
            Ok(())
        } else {
            Err(format!("Failed to unmap {addr}"))
        }
    }
}

#[cfg(feature = "python")]
pub mod pybind {
    use libafl_qemu_sys::{GuestAddr, MmapPerms};
    use pyo3::{
        conversion::FromPyObject,
        exceptions::PyValueError,
        pymethods,
        types::{PyAnyMethods, PyInt},
        Bound, PyObject, PyResult, Python,
    };

    use crate::{pybind::Qemu, qemu::hooks::SyscallHookResult};

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
                    let any = ret.bind(py);
                    if any.is_none() {
                        SyscallHookResult::new(None)
                    } else {
                        let a: Result<&Bound<'_, PyInt>, _> = any.downcast_exact();
                        if let Ok(i) = a {
                            SyscallHookResult::new(Some(
                                i.extract().expect("Invalid syscall hook return value"),
                            ))
                        } else {
                            SyscallHookResult::extract_bound(ret.bind(py))
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

        /// # Safety
        /// Accesses the global `PY_SYSCALL_HOOK` and may not be called concurrently.
        unsafe fn set_syscall_hook(&self, hook: PyObject) {
            unsafe {
                PY_SYSCALL_HOOK = Some(hook);
            }
            self.qemu
                .hooks()
                .add_pre_syscall_hook(0u64, py_syscall_hook_wrapper);
        }
    }
}
