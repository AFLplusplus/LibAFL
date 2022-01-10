//! Expose QEMU user `LibAFL` C api to Rust

use core::{
    convert::Into,
    ffi::c_void,
    mem::{size_of, transmute, MaybeUninit},
    ptr::{copy_nonoverlapping, null},
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use num_traits::Num;
use std::{slice::from_raw_parts, str::from_utf8_unchecked};
use strum_macros::EnumIter;

#[cfg(feature = "python")]
use pyo3::{prelude::*, PyIterProtocol};

pub const SKIP_EXEC_HOOK: u64 = u64::MAX;

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum MmapPerms {
    None = 0,
    Read = libc::PROT_READ,
    Write = libc::PROT_WRITE,
    Execute = libc::PROT_EXEC,
    ReadWrite = libc::PROT_READ | libc::PROT_WRITE,
    ReadExecute = libc::PROT_READ | libc::PROT_EXEC,
    WriteExecute = libc::PROT_WRITE | libc::PROT_EXEC,
    ReadWriteExecute = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
}

impl MmapPerms {
    #[must_use]
    pub fn is_r(&self) -> bool {
        matches!(
            self,
            MmapPerms::Read
                | MmapPerms::ReadWrite
                | MmapPerms::ReadExecute
                | MmapPerms::ReadWriteExecute
        )
    }

    #[must_use]
    pub fn is_w(&self) -> bool {
        matches!(
            self,
            MmapPerms::Write
                | MmapPerms::ReadWrite
                | MmapPerms::WriteExecute
                | MmapPerms::ReadWriteExecute
        )
    }

    #[must_use]
    pub fn is_x(&self) -> bool {
        matches!(
            self,
            MmapPerms::Execute
                | MmapPerms::ReadExecute
                | MmapPerms::WriteExecute
                | MmapPerms::ReadWriteExecute
        )
    }
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for MmapPerms {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}

#[repr(C)]
#[cfg_attr(feature = "python", pyclass)]
#[cfg_attr(feature = "python", derive(FromPyObject))]
pub struct SyscallHookResult {
    pub retval: u64,
    pub skip_syscall: bool,
}

#[cfg(feature = "python")]
#[pymethods]
impl SyscallHookResult {
    #[new]
    #[must_use]
    pub fn new(value: Option<u64>) -> Self {
        value.map_or(
            Self {
                retval: 0,
                skip_syscall: false,
            },
            |v| Self {
                retval: v,
                skip_syscall: true,
            },
        )
    }
}

#[cfg(not(feature = "python"))]
impl SyscallHookResult {
    #[must_use]
    pub fn new(value: Option<u64>) -> Self {
        value.map_or(
            Self {
                retval: 0,
                skip_syscall: false,
            },
            |v| Self {
                retval: v,
                skip_syscall: true,
            },
        )
    }
}

#[repr(C)]
#[cfg_attr(feature = "python", pyclass(unsendable))]
pub struct MapInfo {
    start: u64,
    end: u64,
    offset: u64,
    path: *const u8,
    flags: i32,
    is_priv: i32,
}

#[cfg_attr(feature = "python", pymethods)]
impl MapInfo {
    #[must_use]
    pub fn start(&self) -> u64 {
        self.start
    }

    #[must_use]
    pub fn end(&self) -> u64 {
        self.end
    }

    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        if self.path.is_null() {
            None
        } else {
            unsafe {
                Some(from_utf8_unchecked(from_raw_parts(
                    self.path,
                    strlen(self.path),
                )))
            }
        }
    }

    #[must_use]
    pub fn flags(&self) -> MmapPerms {
        MmapPerms::try_from(self.flags).unwrap()
    }

    #[must_use]
    pub fn is_priv(&self) -> bool {
        self.is_priv != 0
    }
}

extern "C" {
    fn qemu_user_init(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32;

    fn libafl_qemu_write_reg(reg: i32, val: *const u8) -> i32;
    fn libafl_qemu_read_reg(reg: i32, val: *mut u8) -> i32;
    fn libafl_qemu_num_regs() -> i32;
    fn libafl_qemu_set_breakpoint(addr: u64) -> i32;
    fn libafl_qemu_remove_breakpoint(addr: u64) -> i32;
    fn libafl_qemu_set_hook(addr: u64, callback: extern "C" fn(u64), val: u64) -> i32;
    fn libafl_qemu_remove_hook(addr: u64) -> i32;
    fn libafl_qemu_run() -> i32;
    fn libafl_load_addr() -> u64;
    fn libafl_get_brk() -> u64;
    fn libafl_set_brk(brk: u64) -> u64;

    fn strlen(s: *const u8) -> usize;

    /// abi_long target_mmap(abi_ulong start, abi_ulong len, int target_prot, int flags, int fd, abi_ulong offset)
    fn target_mmap(start: u64, len: u64, target_prot: i32, flags: i32, fd: i32, offset: u64)
        -> u64;

    /// int target_munmap(abi_ulong start, abi_ulong len)
    fn target_munmap(start: u64, len: u64) -> i32;

    fn read_self_maps() -> *const c_void;
    fn free_self_maps(map_info: *const c_void);

    fn libafl_maps_next(map_info: *const c_void, ret: *mut MapInfo) -> *const c_void;

    static exec_path: *const u8;
    static guest_base: usize;

    static mut libafl_exec_edge_hook: unsafe extern "C" fn(u64);
    static mut libafl_gen_edge_hook: unsafe extern "C" fn(u64, u64) -> u64;
    static mut libafl_exec_block_hook: unsafe extern "C" fn(u64);
    static mut libafl_gen_block_hook: unsafe extern "C" fn(u64) -> u64;

    static mut libafl_exec_read_hook1: unsafe extern "C" fn(u64, u64);
    static mut libafl_exec_read_hook2: unsafe extern "C" fn(u64, u64);
    static mut libafl_exec_read_hook4: unsafe extern "C" fn(u64, u64);
    static mut libafl_exec_read_hook8: unsafe extern "C" fn(u64, u64);
    static mut libafl_exec_read_hookN: unsafe extern "C" fn(u64, u64, u32);
    static mut libafl_gen_read_hook: unsafe extern "C" fn(u32) -> u64;

    static mut libafl_exec_write_hook1: unsafe extern "C" fn(u64, u64);
    static mut libafl_exec_write_hook2: unsafe extern "C" fn(u64, u64);
    static mut libafl_exec_write_hook4: unsafe extern "C" fn(u64, u64);
    static mut libafl_exec_write_hook8: unsafe extern "C" fn(u64, u64);
    static mut libafl_exec_write_hookN: unsafe extern "C" fn(u64, u64, u32);
    static mut libafl_gen_write_hook: unsafe extern "C" fn(u32) -> u64;

    static mut libafl_exec_cmp_hook1: unsafe extern "C" fn(u64, u8, u8);
    static mut libafl_exec_cmp_hook2: unsafe extern "C" fn(u64, u16, u16);
    static mut libafl_exec_cmp_hook4: unsafe extern "C" fn(u64, u32, u32);
    static mut libafl_exec_cmp_hook8: unsafe extern "C" fn(u64, u64, u64);
    static mut libafl_gen_cmp_hook: unsafe extern "C" fn(u64, u32) -> u64;

    static mut libafl_pre_syscall_hook:
        unsafe extern "C" fn(i32, u64, u64, u64, u64, u64, u64, u64, u64) -> SyscallHookResult;
    static mut libafl_post_syscall_hook:
        unsafe extern "C" fn(u64, i32, u64, u64, u64, u64, u64, u64, u64, u64) -> u64;
}

#[cfg_attr(feature = "python", pyclass(unsendable))]
pub struct GuestMaps {
    orig_c_iter: *const c_void,
    c_iter: *const c_void,
}

// Consider a private new only for Emulator
impl GuestMaps {
    #[must_use]
    pub(crate) fn new() -> Self {
        unsafe {
            let maps = read_self_maps();
            Self {
                orig_c_iter: maps,
                c_iter: maps,
            }
        }
    }
}

impl Iterator for GuestMaps {
    type Item = MapInfo;

    #[allow(clippy::uninit_assumed_init)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.c_iter.is_null() {
            return None;
        }
        unsafe {
            let mut ret: MapInfo = MaybeUninit::uninit().assume_init();
            self.c_iter = libafl_maps_next(self.c_iter, &mut ret as *mut _);
            if self.c_iter.is_null() {
                None
            } else {
                Some(ret)
            }
        }
    }
}

#[cfg(feature = "python")]
#[pyproto]
impl PyIterProtocol for GuestMaps {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }
    fn __next__(mut slf: PyRefMut<Self>) -> Option<PyObject> {
        Python::with_gil(|py| slf.next().map(|x| x.into_py(py)))
    }
}

impl Drop for GuestMaps {
    fn drop(&mut self) {
        unsafe {
            free_self_maps(self.orig_c_iter);
        }
    }
}

static mut EMULATOR_IS_INITIALIZED: bool = false;

#[derive(Debug)]
pub struct Emulator {
    _private: (),
}

#[allow(clippy::unused_self)]
impl Emulator {
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn new(args: &[String], env: &[(String, String)]) -> Emulator {
        unsafe {
            assert!(!EMULATOR_IS_INITIALIZED);
        }
        assert!(!args.is_empty());
        let args: Vec<String> = args.iter().map(|x| x.clone() + "\0").collect();
        let argv: Vec<*const u8> = args.iter().map(|x| x.as_bytes().as_ptr()).collect();
        assert!(argv.len() < i32::MAX as usize);
        let env_strs: Vec<String> = env
            .iter()
            .map(|(k, v)| format!("{}={}\0", &k, &v))
            .collect();
        let mut envp: Vec<*const u8> = env_strs.iter().map(|x| x.as_bytes().as_ptr()).collect();
        envp.push(null());
        #[allow(clippy::cast_possible_wrap)]
        let argc = argv.len() as i32;
        unsafe {
            qemu_user_init(
                argc,
                argv.as_ptr() as *const *const u8,
                envp.as_ptr() as *const *const u8,
            );
            EMULATOR_IS_INITIALIZED = true;
        }
        Emulator { _private: () }
    }

    #[must_use]
    pub(crate) fn new_empty() -> Emulator {
        Emulator { _private: () }
    }

    #[must_use]
    pub fn mappings(&self) -> GuestMaps {
        GuestMaps::new()
    }

    pub unsafe fn write_mem<T>(&self, addr: u64, buf: &[T]) {
        let host_addr = self.g2h(addr);
        copy_nonoverlapping(
            buf.as_ptr() as *const _ as *const u8,
            host_addr,
            buf.len() * size_of::<T>(),
        );
    }

    pub unsafe fn read_mem<T>(&self, addr: u64, buf: &mut [T]) {
        let host_addr = self.g2h(addr);
        copy_nonoverlapping(
            host_addr as *const u8,
            buf.as_mut_ptr() as *mut _ as *mut u8,
            buf.len() * size_of::<T>(),
        );
    }

    #[must_use]
    pub fn num_regs(&self) -> i32 {
        unsafe { libafl_qemu_num_regs() }
    }

    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), String>
    where
        T: Num + PartialOrd + Copy,
        R: Into<i32>,
    {
        let reg = reg.into();
        let success = unsafe { libafl_qemu_write_reg(reg, &val as *const _ as *const u8) };
        if success == 0 {
            Err(format!("Failed to write to register {}", reg))
        } else {
            Ok(())
        }
    }

    pub fn read_reg<R, T>(&self, reg: R) -> Result<T, String>
    where
        T: Num + PartialOrd + Copy,
        R: Into<i32>,
    {
        let reg = reg.into();
        let mut val = T::zero();
        let success = unsafe { libafl_qemu_read_reg(reg, &mut val as *mut _ as *mut u8) };
        if success == 0 {
            Err(format!("Failed to read register {}", reg))
        } else {
            Ok(val)
        }
    }

    pub fn set_breakpoint(&self, addr: u64) {
        unsafe {
            libafl_qemu_set_breakpoint(addr);
        }
    }

    pub fn remove_breakpoint(&self, addr: u64) {
        unsafe {
            libafl_qemu_remove_breakpoint(addr);
        }
    }

    pub fn set_hook(&self, addr: u64, callback: extern "C" fn(u64), val: u64) {
        unsafe {
            libafl_qemu_set_hook(addr, callback, val);
        }
    }

    pub fn remove_hook(&self, addr: u64) {
        unsafe {
            libafl_qemu_remove_hook(addr);
        }
    }

    pub unsafe fn run(&self) {
        libafl_qemu_run();
    }

    #[must_use]
    pub fn g2h<T>(&self, addr: u64) -> *mut T {
        unsafe { transmute(addr + guest_base as u64) }
    }

    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> u64 {
        unsafe { (addr as usize - guest_base) as u64 }
    }

    #[must_use]
    pub fn binary_path<'a>(&self) -> &'a str {
        unsafe { from_utf8_unchecked(from_raw_parts(exec_path, strlen(exec_path))) }
    }

    #[must_use]
    pub fn load_addr(&self) -> u64 {
        unsafe { libafl_load_addr() }
    }

    #[must_use]
    pub fn get_brk(&self) -> u64 {
        unsafe { libafl_get_brk() }
    }

    pub fn set_brk(&self, brk: u64) {
        unsafe { libafl_set_brk(brk) };
    }

    pub fn map_private(&self, addr: u64, size: usize, perms: MmapPerms) -> Result<u64, String> {
        let res = unsafe {
            target_mmap(
                addr,
                size as u64,
                perms.into(),
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if res == 0 {
            Err(format!("Failed to map {}", addr))
        } else {
            Ok(res)
        }
    }

    pub fn unmap(&self, addr: u64, size: usize) -> Result<(), String> {
        if unsafe { target_munmap(addr, size as u64) } == 0 {
            Ok(())
        } else {
            Err(format!("Failed to unmap {}", addr))
        }
    }

    // TODO add has_X_hook() and panic when setting a hook for the second time

    pub fn set_exec_edge_hook(&self, hook: extern "C" fn(id: u64)) {
        unsafe {
            libafl_exec_edge_hook = hook;
        }
    }

    pub fn set_gen_edge_hook(&self, hook: extern "C" fn(src: u64, dest: u64) -> u64) {
        unsafe {
            libafl_gen_edge_hook = hook;
        }
    }

    pub fn set_exec_block_hook(&self, hook: extern "C" fn(pc: u64)) {
        unsafe {
            libafl_exec_block_hook = hook;
        }
    }

    pub fn set_gen_block_hook(&self, hook: extern "C" fn(pc: u64) -> u64) {
        unsafe {
            libafl_gen_block_hook = hook;
        }
    }

    pub fn set_exec_read1_hook(&self, hook: extern "C" fn(id: u64, addr: u64)) {
        unsafe {
            libafl_exec_read_hook1 = hook;
        }
    }

    pub fn set_exec_read2_hook(&self, hook: extern "C" fn(id: u64, addr: u64)) {
        unsafe {
            libafl_exec_read_hook2 = hook;
        }
    }

    pub fn set_exec_read4_hook(&self, hook: extern "C" fn(id: u64, addr: u64)) {
        unsafe {
            libafl_exec_read_hook4 = hook;
        }
    }

    pub fn set_exec_read8_hook(&self, hook: extern "C" fn(id: u64, addr: u64)) {
        unsafe {
            libafl_exec_read_hook8 = hook;
        }
    }

    pub fn set_exec_read_n_hook(&self, hook: extern "C" fn(id: u64, addr: u64, size: u32)) {
        unsafe {
            libafl_exec_read_hookN = hook;
        }
    }

    pub fn set_gen_read_hook(&self, hook: extern "C" fn(size: u32) -> u64) {
        unsafe {
            libafl_gen_read_hook = hook;
        }
    }

    pub fn set_exec_write1_hook(&self, hook: extern "C" fn(id: u64, addr: u64)) {
        unsafe {
            libafl_exec_write_hook1 = hook;
        }
    }

    pub fn set_exec_write2_hook(&self, hook: extern "C" fn(id: u64, addr: u64)) {
        unsafe {
            libafl_exec_write_hook2 = hook;
        }
    }

    pub fn set_exec_write4_hook(&self, hook: extern "C" fn(id: u64, addr: u64)) {
        unsafe {
            libafl_exec_write_hook4 = hook;
        }
    }

    pub fn set_exec_write8_hook(&self, hook: extern "C" fn(id: u64, addr: u64)) {
        unsafe {
            libafl_exec_write_hook8 = hook;
        }
    }

    pub fn set_exec_write_n_hook(&self, hook: extern "C" fn(id: u64, addr: u64, size: u32)) {
        unsafe {
            libafl_exec_write_hookN = hook;
        }
    }

    // TODO add pc arg
    pub fn set_gen_write_hook(&self, hook: extern "C" fn(size: u32) -> u64) {
        unsafe {
            libafl_gen_write_hook = hook;
        }
    }

    pub fn set_exec_cmp1_hook(&self, hook: extern "C" fn(id: u64, v0: u8, v1: u8)) {
        unsafe {
            libafl_exec_cmp_hook1 = hook;
        }
    }

    pub fn set_exec_cmp2_hook(&self, hook: extern "C" fn(id: u64, v0: u16, v1: u16)) {
        unsafe {
            libafl_exec_cmp_hook2 = hook;
        }
    }

    pub fn set_exec_cmp4_hook(&self, hook: extern "C" fn(id: u64, v0: u32, v1: u32)) {
        unsafe {
            libafl_exec_cmp_hook4 = hook;
        }
    }

    pub fn set_exec_cmp8_hook(&self, hook: extern "C" fn(id: u64, v0: u64, v1: u64)) {
        unsafe {
            libafl_exec_cmp_hook8 = hook;
        }
    }

    pub fn set_gen_cmp_hook(&self, hook: extern "C" fn(pc: u64, size: u32) -> u64) {
        unsafe {
            libafl_gen_cmp_hook = hook;
        }
    }

    pub fn set_pre_syscall_hook(
        &self,
        hook: extern "C" fn(i32, u64, u64, u64, u64, u64, u64, u64, u64) -> SyscallHookResult,
    ) {
        unsafe {
            libafl_pre_syscall_hook = hook;
        }
    }

    pub fn set_post_syscall_hook(
        &self,
        hook: extern "C" fn(u64, i32, u64, u64, u64, u64, u64, u64, u64, u64) -> u64,
    ) {
        unsafe {
            libafl_post_syscall_hook = hook;
        }
    }
}

#[cfg(feature = "python")]
pub mod pybind {
    use super::{MmapPerms, SyscallHookResult};
    use core::mem::transmute;
    use pyo3::exceptions::PyValueError;
    use pyo3::{prelude::*, types::PyInt};
    use std::convert::TryFrom;

    static mut PY_SYSCALL_HOOK: Option<PyObject> = None;
    static mut PY_GENERIC_HOOKS: Vec<(u64, PyObject)> = vec![];

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
                        let a: Result<&PyInt, _> = any.cast_as();
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

    extern "C" fn py_generic_hook_wrapper(idx: u64) {
        let obj = unsafe { &PY_GENERIC_HOOKS[idx as usize].1 };
        Python::with_gil(|py| {
            obj.call0(py).expect("Error in the hook");
        });
    }

    #[pyclass(unsendable)]
    pub struct Emulator {
        pub emu: super::Emulator,
    }

    #[pymethods]
    impl Emulator {
        #[allow(clippy::needless_pass_by_value)]
        #[new]
        fn new(args: Vec<String>, env: Vec<(String, String)>) -> Emulator {
            Emulator {
                emu: super::Emulator::new(&args, &env),
            }
        }

        fn write_mem(&self, addr: u64, buf: &[u8]) {
            unsafe {
                self.emu.write_mem(addr, buf);
            }
        }

        fn read_mem(&self, addr: u64, size: usize) -> Vec<u8> {
            let mut buf = vec![0; size];
            unsafe {
                self.emu.read_mem(addr, &mut buf);
            }
            buf
        }

        fn num_regs(&self) -> i32 {
            self.emu.num_regs()
        }

        fn write_reg(&self, reg: i32, val: u64) -> PyResult<()> {
            self.emu.write_reg(reg, val).map_err(PyValueError::new_err)
        }

        fn read_reg(&self, reg: i32) -> PyResult<u64> {
            self.emu.read_reg(reg).map_err(PyValueError::new_err)
        }

        fn set_breakpoint(&self, addr: u64) {
            self.emu.set_breakpoint(addr);
        }

        fn remove_breakpoint(&self, addr: u64) {
            self.emu.remove_breakpoint(addr);
        }

        fn run(&self) {
            unsafe {
                self.emu.run();
            }
        }

        fn g2h(&self, addr: u64) -> u64 {
            self.emu.g2h::<*const u8>(addr) as u64
        }

        fn h2g(&self, addr: u64) -> u64 {
            self.emu.h2g(unsafe { transmute::<_, *const u8>(addr) })
        }

        fn binary_path(&self) -> String {
            self.emu.binary_path().to_owned()
        }

        fn load_addr(&self) -> u64 {
            self.emu.load_addr()
        }

        fn map_private(&self, addr: u64, size: usize, perms: i32) -> PyResult<u64> {
            if let Ok(p) = MmapPerms::try_from(perms) {
                self.emu
                    .map_private(addr, size, p)
                    .map_err(PyValueError::new_err)
            } else {
                Err(PyValueError::new_err("Invalid perms"))
            }
        }

        fn unmap(&self, addr: u64, size: usize) -> PyResult<()> {
            self.emu.unmap(addr, size).map_err(PyValueError::new_err)
        }

        fn set_syscall_hook(&self, hook: PyObject) {
            unsafe {
                PY_SYSCALL_HOOK = Some(hook);
            }
            self.emu.set_pre_syscall_hook(py_syscall_hook_wrapper);
        }

        fn set_hook(&self, addr: u64, hook: PyObject) {
            unsafe {
                let idx = PY_GENERIC_HOOKS.len();
                PY_GENERIC_HOOKS.push((addr, hook));
                self.emu.set_hook(addr, py_generic_hook_wrapper, idx as u64);
            }
        }

        fn remove_hook(&self, addr: u64) {
            unsafe {
                PY_GENERIC_HOOKS.retain(|(a, _)| *a != addr);
            }
            self.emu.remove_hook(addr);
        }
    }
}
