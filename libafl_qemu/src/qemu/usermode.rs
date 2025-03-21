use std::{
    ffi::c_void, mem::MaybeUninit, ops::Range, ptr::copy_nonoverlapping, slice::from_raw_parts_mut,
    str::from_utf8_unchecked_mut,
};

use libafl_bolts::{Error, os::unix_signals::Signal};
use libafl_qemu_sys::{
    GuestAddr, GuestUsize, IntervalTreeNode, IntervalTreeRoot, MapInfo, MmapPerms, VerifyAccess,
    exec_path, free_self_maps, guest_base, libafl_force_dfl, libafl_get_brk,
    libafl_get_initial_brk, libafl_load_addr, libafl_maps_first, libafl_maps_next, libafl_qemu_run,
    libafl_set_brk, mmap_next_start, pageflags_get_root, read_self_maps,
};
use libc::{c_int, c_uchar, siginfo_t, strlen};
#[cfg(feature = "python")]
use pyo3::{IntoPyObject, Py, PyRef, PyRefMut, Python, pyclass, pymethods};

use crate::{CPU, Qemu, qemu::QEMU_IS_RUNNING};

/// Choose how QEMU target signals should be handled.
/// It's main use is to describe how crashes and timeouts should be treated.
pub enum TargetSignalHandling {
    /// Return to harness with the associated exit request on target crashing or timeout signal.
    /// The snapshot mechanism should make sure to recover correctly from the crash.
    /// For instance, snapshots do not take into account side effects related to file descriptors.
    /// If it could have an impact in case of a crash, prefer the other policy.
    ///
    /// *Warning*: this policy should be used with [`SnapshotModule`]. It can be used without
    /// snapshotting, but it is up to the user to make sure the recovery is possible without
    /// corrupting the target.
    ReturnToHarness,
    /// Propagate target signal to host (following QEMU target to host signal translation) by
    /// raising the proper signal.
    /// This the safe policy, since the target is completely reset.
    /// However, it could make the fuzzer much slower if many crashes are triggered during the
    /// fuzzing campaign.
    RaiseSignal,
}

pub struct QemuMappingsViewer<'a> {
    qemu: &'a Qemu,
    mappings: Vec<MapInfo>,
}

impl Default for TargetSignalHandling {
    /// Historically, `LibAFL` QEMU raises the target signal to the host.
    fn default() -> Self {
        TargetSignalHandling::RaiseSignal
    }
}

impl<'a> QemuMappingsViewer<'a> {
    /// Capture the memory mappings of Qemu at the moment when we create this object
    /// Thus if qemu make updates to the mappings, they won't be reflected to this object.
    #[must_use]
    pub fn new(qemu: &'a Qemu) -> Self {
        let mut mappings: Vec<MapInfo> = vec![];
        for m in qemu.mappings() {
            mappings.push(m);
        }
        Self { qemu, mappings }
    }

    /// Update the mappings
    pub fn update(&mut self) {
        let mut mappings: Vec<MapInfo> = vec![];
        for m in self.qemu.mappings() {
            mappings.push(m);
        }
        self.mappings = mappings;
    }

    #[must_use]
    pub fn mappings(&self) -> &[MapInfo] {
        &self.mappings
    }
}

impl core::fmt::Debug for QemuMappingsViewer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for m in &self.mappings {
            let flags = format!("Flags: {:?}", m.flags());
            let padded = format!("{flags:<20}");
            writeln!(
                f,
                "Mapping: 0x{:016x}-0x{:016x}, {:>10} IsPriv: {:?} Path: {}",
                m.start(),
                m.end(),
                padded,
                m.is_priv(),
                m.path().unwrap_or(&"<EMPTY>".to_string())
            )?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "python", pyclass(unsendable))]
pub struct GuestMaps {
    self_maps_root: *mut IntervalTreeRoot,
    pageflags_node: *mut IntervalTreeNode,
}

/// Information about the image loaded by QEMU.
pub struct ImageInfo {
    pub code: Range<GuestAddr>,
    pub data: Range<GuestAddr>,
    pub stack: Range<GuestAddr>,
    pub vdso: GuestAddr,
    pub entry: GuestAddr,
    pub brk: GuestAddr,
    pub exec_stack: bool,
}

pub enum QemuSignalContext {
    /// We are not in QEMU's signal handler, no signal is being propagated.
    OutOfQemuSignalHandler,
    /// We are propagating a host signal from QEMU signal handler.
    InQemuSignalHandlerHost,
    /// We are propagating a target signal from QEMU signal handler
    InQemuSignalHandlerTarget,
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

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut ret = MaybeUninit::uninit();

            self.pageflags_node =
                libafl_maps_next(self.pageflags_node, self.self_maps_root, ret.as_mut_ptr());

            let ret = ret.assume_init();

            if ret.is_valid { Some(ret.into()) } else { None }
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
        unsafe {
            let host_addr = Qemu::get().unwrap().g2h(addr);
            copy_nonoverlapping(host_addr, buf.as_mut_ptr(), buf.len());
        }
    }

    /// Write a value to a guest address.
    /// The input address in not checked for validity.
    ///
    /// # Safety
    /// This will write to a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn write_mem_unchecked(&self, addr: GuestAddr, buf: &[u8]) {
        unsafe {
            let host_addr = Qemu::get().unwrap().g2h(addr);
            copy_nonoverlapping(buf.as_ptr(), host_addr, buf.len());
        }
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

#[expect(clippy::unused_self)]
impl Qemu {
    #[must_use]
    pub fn mappings(&self) -> GuestMaps {
        GuestMaps::new()
    }

    #[must_use]
    pub fn image_info(&self) -> ImageInfo {
        // # Safety
        // Safe because QEMU has been correctly initialized since it takes self as parameter.
        let image_info = unsafe { *libafl_qemu_sys::libafl_get_image_info() };

        let code_start = image_info.start_code;
        let code_end = image_info.end_code;

        let data_start = image_info.start_data;
        let data_end = image_info.end_data;

        let stack_start = image_info.stack_limit;
        let stack_end = image_info.start_stack;

        ImageInfo {
            code: code_start..code_end,
            data: data_start..data_end,
            stack: stack_start..stack_end,
            vdso: image_info.vdso,
            entry: image_info.entry,
            brk: image_info.brk,
            exec_stack: image_info.exec_stack,
        }
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
        unsafe {
            libafl_qemu_run();
        }
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

    #[must_use]
    pub fn get_initial_brk(&self) -> GuestAddr {
        unsafe { libafl_get_initial_brk() as GuestAddr }
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

    #[expect(clippy::cast_sign_loss)]
    pub fn mmap(
        self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
        flags: c_int,
        fd: i32,
    ) -> Result<GuestAddr, Error> {
        let res = unsafe {
            libafl_qemu_sys::target_mmap(addr, size as GuestUsize, perms.into(), flags, fd, 0)
        };
        if res <= 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            Err(Error::illegal_argument(format!(
                "failed to mmap addr: {addr:x} (size: {size:?} prot: {perms:?} flags: {flags:?} fd: {fd:?}). The errno is {errno:?}",
            )))
        } else {
            Ok(res as GuestAddr)
        }
    }

    pub fn map_private(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, Error> {
        self.mmap(
            addr,
            size,
            perms,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
        )
    }

    pub fn map_fixed(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, Error> {
        self.mmap(
            addr,
            size,
            perms,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
        )
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

    #[must_use]
    pub fn signal_ctx(&self) -> QemuSignalContext {
        unsafe {
            let qemu_signal_ctx = *libafl_qemu_sys::libafl_qemu_signal_context();

            if qemu_signal_ctx.in_qemu_sig_hdlr {
                if qemu_signal_ctx.is_target_signal {
                    QemuSignalContext::InQemuSignalHandlerTarget
                } else {
                    QemuSignalContext::InQemuSignalHandlerHost
                }
            } else {
                QemuSignalContext::OutOfQemuSignalHandler
            }
        }
    }

    /// Runs QEMU signal's handler
    /// If it is already running, returns true.
    /// In that case, it would most likely mean we are in a signal loop.
    ///
    /// # Safety
    ///
    /// Run QEMU's native signal handler.
    ///
    /// Needlessly to say, it should be used very carefully.
    /// It will run QEMU's signal handler, and maybe propagate new signals.
    pub(crate) unsafe fn run_signal_handler(
        &self,
        host_sig: c_int,
        info: *mut siginfo_t,
        puc: *mut c_void,
    ) {
        unsafe {
            libafl_qemu_sys::libafl_qemu_native_signal_handler(host_sig, info, puc);
        }
    }

    /// Emulate a signal coming from the target
    ///
    /// # Safety
    ///
    /// This may raise a signal to host. Some signals could have a funky behaviour.
    /// SIGSEGV is safe to use.
    pub unsafe fn target_signal(&self, signal: Signal) {
        unsafe {
            QEMU_IS_RUNNING = true;
            libafl_qemu_sys::libafl_set_in_target_signal_ctx();
            libc::raise(signal.into());
        }
    }

    /// Set the target crash handling policy according to [`TargetSignalHandling`]'s documentation.
    ///
    /// # Safety
    ///
    /// It has an important impact on how crashes are handled by QEMU on target crashing signals.
    /// Please make sure to read the documentation of [`TargetSignalHandling`] before touching
    /// this.
    pub unsafe fn set_target_crash_handling(&self, handling: &TargetSignalHandling) {
        match handling {
            TargetSignalHandling::ReturnToHarness => unsafe {
                libafl_qemu_sys::libafl_set_return_on_crash(true);
            },
            TargetSignalHandling::RaiseSignal => unsafe {
                libafl_qemu_sys::libafl_set_return_on_crash(false);
            },
        }
    }
}

#[cfg(feature = "python")]
pub mod pybind {
    use libafl_qemu_sys::{GuestAddr, MmapPerms};
    use pyo3::{
        Bound, PyObject, PyResult, Python,
        conversion::FromPyObject,
        exceptions::PyValueError,
        pymethods,
        types::{PyAnyMethods, PyInt},
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
        unsafe { (&raw const PY_SYSCALL_HOOK).read() }.map_or_else(
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
                    .map_err(|_| PyValueError::new_err("Failed to mmap"))
            } else {
                Err(PyValueError::new_err("Invalid perms"))
            }
        }

        fn map_fixed(&self, addr: GuestAddr, size: usize, perms: i32) -> PyResult<GuestAddr> {
            if let Ok(p) = MmapPerms::try_from(perms) {
                self.qemu
                    .map_private(addr, size, p)
                    .map_err(|_| PyValueError::new_err("Failed to mmap"))
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
