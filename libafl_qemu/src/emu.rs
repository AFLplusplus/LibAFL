//! Expose QEMU user `LibAFL` C api to Rust

use core::{
    convert::Into,
    ffi::c_void,
    fmt,
    mem::MaybeUninit,
    ptr::{addr_of, copy_nonoverlapping, null},
};
#[cfg(emulation_mode = "systemmode")]
use std::ffi::CString;
use std::{slice::from_raw_parts, str::from_utf8_unchecked};

#[cfg(emulation_mode = "usermode")]
use libc::c_int;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use num_traits::Num;
use strum_macros::EnumIter;

pub type GuestAddr = libafl_qemu_sys::target_ulong;
pub type GuestUsize = libafl_qemu_sys::target_ulong;
pub type GuestIsize = libafl_qemu_sys::target_long;
pub type GuestVirtAddr = libafl_qemu_sys::hwaddr;
pub type GuestPhysAddr = libafl_qemu_sys::hwaddr;

pub type GuestHwAddrInfo = libafl_qemu_sys::qemu_plugin_hwaddr;

#[cfg(emulation_mode = "systemmode")]
pub type FastSnapshot = *mut libafl_qemu_sys::syx_snapshot_t;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct MemAccessInfo {
    oi: libafl_qemu_sys::MemOpIdx,
}

impl MemAccessInfo {
    #[must_use]
    pub fn memop(&self) -> libafl_qemu_sys::MemOp {
        libafl_qemu_sys::MemOp(self.oi >> 4)
    }

    #[must_use]
    pub fn memopidx(&self) -> libafl_qemu_sys::MemOpIdx {
        self.oi
    }

    #[must_use]
    pub fn mmu_index(&self) -> u32 {
        self.oi & 15
    }

    #[must_use]
    pub fn size(&self) -> usize {
        libafl_qemu_sys::memop_size(self.memop()) as usize
    }

    #[must_use]
    pub fn is_big_endian(&self) -> bool {
        libafl_qemu_sys::memop_big_endian(self.memop())
    }

    #[must_use]
    pub fn encode_with(&self, other: u32) -> u64 {
        (u64::from(self.oi) << 32) | u64::from(other)
    }

    #[must_use]
    pub fn decode_from(encoded: u64) -> (Self, u32) {
        let low = (encoded & 0xFFFFFFFF) as u32;
        let high = (encoded >> 32) as u32;
        (Self { oi: high }, low)
    }

    #[must_use]
    pub fn new(oi: libafl_qemu_sys::MemOpIdx) -> Self {
        Self { oi }
    }
}

impl From<libafl_qemu_sys::MemOpIdx> for MemAccessInfo {
    fn from(oi: libafl_qemu_sys::MemOpIdx) -> Self {
        Self { oi }
    }
}

#[cfg(feature = "python")]
use pyo3::prelude::*;

pub const SKIP_EXEC_HOOK: u64 = u64::MAX;

pub use libafl_qemu_sys::{CPUArchState, CPUState};

pub type CPUStatePtr = *mut libafl_qemu_sys::CPUState;
pub type CPUArchStatePtr = *mut libafl_qemu_sys::CPUArchState;

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter, PartialEq, Eq)]
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
    start: GuestAddr,
    end: GuestAddr,
    offset: GuestAddr,
    path: *const u8,
    flags: i32,
    is_priv: i32,
}

#[cfg_attr(feature = "python", pymethods)]
impl MapInfo {
    #[must_use]
    pub fn start(&self) -> GuestAddr {
        self.start
    }

    #[must_use]
    pub fn end(&self) -> GuestAddr {
        self.end
    }

    #[must_use]
    pub fn offset(&self) -> GuestAddr {
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

#[cfg(emulation_mode = "usermode")]
extern "C" {
    fn qemu_user_init(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32;

    fn libafl_qemu_run() -> i32;

    fn libafl_load_addr() -> u64;
    fn libafl_get_brk() -> u64;
    fn libafl_set_brk(brk: u64) -> u64;

    fn read_self_maps() -> *const c_void;
    fn free_self_maps(map_info: *const c_void);

    fn libafl_maps_next(map_info: *const c_void, ret: *mut MapInfo) -> *const c_void;

    static exec_path: *const u8;
    static guest_base: usize;
    static mut mmap_next_start: GuestAddr;

    static mut libafl_on_thread_hook: unsafe extern "C" fn(u32);

    static mut libafl_pre_syscall_hook:
        unsafe extern "C" fn(i32, u64, u64, u64, u64, u64, u64, u64, u64) -> SyscallHookResult;
    static mut libafl_post_syscall_hook:
        unsafe extern "C" fn(u64, i32, u64, u64, u64, u64, u64, u64, u64, u64) -> u64;
}

#[cfg(emulation_mode = "systemmode")]
extern "C" {
    fn qemu_init(argc: i32, argv: *const *const u8, envp: *const *const u8);

    fn vm_start();
    fn qemu_main_loop();
    fn qemu_cleanup();

    fn libafl_save_qemu_snapshot(name: *const u8, sync: bool);
    fn libafl_load_qemu_snapshot(name: *const u8, sync: bool);
}

#[cfg(emulation_mode = "systemmode")]
extern "C" fn qemu_cleanup_atexit() {
    unsafe {
        qemu_cleanup();
    }
}

extern "C" {
    //static libafl_page_size: GuestUsize;
    fn libafl_page_from_addr(addr: GuestAddr) -> GuestAddr;

    // CPUState* libafl_qemu_get_cpu(int cpu_index);
    fn libafl_qemu_get_cpu(cpu_index: i32) -> CPUStatePtr;
    // int libafl_qemu_num_cpus(void);
    fn libafl_qemu_num_cpus() -> i32;
    // CPUState* libafl_qemu_current_cpu(void);
    fn libafl_qemu_current_cpu() -> CPUStatePtr;

    fn libafl_qemu_cpu_index(cpu: CPUStatePtr) -> i32;

    fn libafl_qemu_write_reg(cpu: CPUStatePtr, reg: i32, val: *const u8) -> i32;
    fn libafl_qemu_read_reg(cpu: CPUStatePtr, reg: i32, val: *mut u8) -> i32;
    fn libafl_qemu_num_regs(cpu: CPUStatePtr) -> i32;

    fn libafl_qemu_set_breakpoint(addr: u64) -> i32;
    fn libafl_qemu_remove_breakpoint(addr: u64) -> i32;
    fn libafl_flush_jit();
    fn libafl_qemu_trigger_breakpoint(cpu: CPUStatePtr);

    fn libafl_qemu_set_hook(
        addr: GuestAddr,
        callback: extern "C" fn(GuestAddr, u64),
        data: u64,
        invalidate_block: i32,
    ) -> usize;
    // fn libafl_qemu_remove_hook(num: usize, invalidate_block: i32) -> i32;
    fn libafl_qemu_remove_hooks_at(addr: GuestAddr, invalidate_block: i32) -> usize;

    fn strlen(s: *const u8) -> usize;

    // void libafl_add_edge_hook(uint64_t (*gen)(target_ulong src, target_ulong dst), void (*exec)(uint64_t id));
    fn libafl_add_edge_hook(
        gen: Option<extern "C" fn(GuestAddr, GuestAddr, u64) -> u64>,
        exec: Option<extern "C" fn(u64, u64)>,
        data: u64,
    );

    // void libafl_add_block_hook(uint64_t (*gen)(target_ulong pc), void (*exec)(uint64_t id));
    fn libafl_add_block_hook(
        gen: Option<extern "C" fn(GuestAddr, u64) -> u64>,
        exec: Option<extern "C" fn(u64, u64)>,
        data: u64,
    );

    // void libafl_add_read_hook(uint64_t (*gen)(target_ulong pc, size_t size, uint64_t data),
    //                      void (*exec1)(uint64_t id, target_ulong addr, uint64_t data),
    //                      void (*exec2)(uint64_t id, target_ulong addr, uint64_t data),
    //                      void (*exec4)(uint64_t id, target_ulong addr, uint64_t data),
    //                      void (*exec8)(uint64_t id, target_ulong addr, uint64_t data),
    //                      void (*exec_n)(uint64_t id, target_ulong addr, size_t size, uint64_t data),
    //                      uint64_t data);
    fn libafl_add_read_hook(
        gen: Option<extern "C" fn(GuestAddr, MemAccessInfo, u64) -> u64>,
        exec1: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec2: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec4: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec8: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec_n: Option<extern "C" fn(u64, GuestAddr, usize, u64)>,
        data: u64,
    );

    // void libafl_add_write_hook(uint64_t (*gen)(target_ulong pc, size_t size, uint64_t data),
    //                      void (*exec1)(uint64_t id, target_ulong addr, uint64_t data),
    //                      void (*exec2)(uint64_t id, target_ulong addr, uint64_t data),
    //                      void (*exec4)(uint64_t id, target_ulong addr, uint64_t data),
    //                      void (*exec8)(uint64_t id, target_ulong addr, uint64_t data),
    //                      void (*exec_n)(uint64_t id, target_ulong addr, size_t size, uint64_t data),
    //                      uint64_t data);
    fn libafl_add_write_hook(
        gen: Option<extern "C" fn(GuestAddr, MemAccessInfo, u64) -> u64>,
        exec1: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec2: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec4: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec8: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec_n: Option<extern "C" fn(u64, GuestAddr, usize, u64)>,
        data: u64,
    );

    // void libafl_add_cmp_hook(uint64_t (*gen)(target_ulong pc, size_t size, uint64_t data),
    //                      void (*exec1)(uint64_t id, uint8_t v0, uint8_t v1, uint64_t data),
    //                      void (*exec2)(uint64_t id, uint16_t v0, uint16_t v1, uint64_t data),
    //                      void (*exec4)(uint64_t id, uint32_t v0, uint32_t v1, uint64_t data),
    //                      void (*exec8)(uint64_t id, uint64_t v0, uint64_t v1, uint64_t data),
    //                      uint64_t data);
    fn libafl_add_cmp_hook(
        gen: Option<extern "C" fn(GuestAddr, usize, u64) -> u64>,
        exec1: Option<extern "C" fn(u64, u8, u8, u64)>,
        exec2: Option<extern "C" fn(u64, u16, u16, u64)>,
        exec4: Option<extern "C" fn(u64, u32, u32, u64)>,
        exec8: Option<extern "C" fn(u64, u64, u64, u64)>,
        data: u64,
    );

    // void libafl_add_backdoor_hook(void (*exec)(uint64_t id, uint64_t data),
    //                           uint64_t data)
    fn libafl_add_backdoor_hook(exec: extern "C" fn(GuestAddr, u64), data: u64);

    fn libafl_qemu_add_gdb_cmd(
        callback: extern "C" fn(*const u8, usize, *const ()) -> i32,
        data: *const (),
    );
    fn libafl_qemu_gdb_reply(buf: *const u8, len: usize);
}

#[cfg(emulation_mode = "usermode")]
#[cfg_attr(feature = "python", pyclass(unsendable))]
pub struct GuestMaps {
    orig_c_iter: *const c_void,
    c_iter: *const c_void,
}

// Consider a private new only for Emulator
#[cfg(emulation_mode = "usermode")]
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

#[cfg(emulation_mode = "usermode")]
impl Iterator for GuestMaps {
    type Item = MapInfo;

    #[allow(clippy::uninit_assumed_init)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.c_iter.is_null() {
            return None;
        }
        unsafe {
            let mut ret = MaybeUninit::uninit();
            self.c_iter = libafl_maps_next(self.c_iter, ret.as_mut_ptr());
            if self.c_iter.is_null() {
                None
            } else {
                Some(ret.assume_init())
            }
        }
    }
}

#[cfg(all(emulation_mode = "usermode", feature = "python"))]
#[pymethods]
impl GuestMaps {
    fn __iter__(slf: PyRef<Self>) -> PyRef<Self> {
        slf
    }
    fn __next__(mut slf: PyRefMut<Self>) -> Option<PyObject> {
        Python::with_gil(|py| slf.next().map(|x| x.into_py(py)))
    }
}

#[cfg(emulation_mode = "usermode")]
impl Drop for GuestMaps {
    fn drop(&mut self) {
        unsafe {
            free_self_maps(self.orig_c_iter);
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FatPtr(pub *const c_void, pub *const c_void);

static mut GDB_COMMANDS: Vec<FatPtr> = vec![];

extern "C" fn gdb_cmd(buf: *const u8, len: usize, data: *const ()) -> i32 {
    unsafe {
        let closure = &mut *(data as *mut Box<dyn for<'r> FnMut(&Emulator, &'r str) -> bool>);
        let cmd = std::str::from_utf8_unchecked(std::slice::from_raw_parts(buf, len));
        let emu = Emulator::new_empty();
        i32::from(closure(&emu, cmd))
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct CPU {
    ptr: CPUStatePtr,
}

#[allow(clippy::unused_self)]
impl CPU {
    #[must_use]
    pub fn emulator(&self) -> Emulator {
        Emulator::new_empty()
    }

    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn index(&self) -> usize {
        unsafe { libafl_qemu_cpu_index(self.ptr) as usize }
    }

    pub fn trigger_breakpoint(&self) {
        unsafe {
            libafl_qemu_trigger_breakpoint(self.ptr);
        }
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn g2h<T>(&self, addr: GuestAddr) -> *mut T {
        unsafe { (addr as usize + guest_base) as *mut T }
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> GuestAddr {
        unsafe { (addr as usize - guest_base) as GuestAddr }
    }

    #[cfg(emulation_mode = "systemmode")]
    #[must_use]
    pub fn get_phys_addr(&self, vaddr: GuestAddr) -> Option<GuestPhysAddr> {
        unsafe {
            let page = libafl_page_from_addr(vaddr);
            let mut attrs = MaybeUninit::<libafl_qemu_sys::MemTxAttrs>::uninit();
            let paddr = libafl_qemu_sys::cpu_get_phys_page_attrs_debug(
                self.ptr,
                page as GuestVirtAddr,
                attrs.as_mut_ptr(),
            );
            if paddr == (-1i64 as GuestPhysAddr) {
                None
            } else {
                Some(paddr)
            }
        }
    }

    #[cfg(emulation_mode = "systemmode")]
    #[must_use]
    pub fn get_phys_addr_tlb(
        &self,
        vaddr: GuestAddr,
        info: MemAccessInfo,
        is_store: bool,
    ) -> Option<GuestPhysAddr> {
        unsafe {
            let pminfo = libafl_qemu_sys::make_plugin_meminfo(
                info.oi,
                if is_store {
                    libafl_qemu_sys::qemu_plugin_mem_rw_QEMU_PLUGIN_MEM_W
                } else {
                    libafl_qemu_sys::qemu_plugin_mem_rw_QEMU_PLUGIN_MEM_R
                },
            );
            let phwaddr = libafl_qemu_sys::qemu_plugin_get_hwaddr(pminfo, vaddr as GuestVirtAddr);
            if phwaddr.is_null() {
                None
            } else {
                Some(libafl_qemu_sys::qemu_plugin_hwaddr_phys_addr(phwaddr) as GuestPhysAddr)
            }
        }
    }

    // TODO expose tlb_set_dirty and tlb_reset_dirty

    /// Write a value to a guest address.
    ///
    /// # Safety
    /// This will write to a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
        #[cfg(emulation_mode = "usermode")]
        {
            let host_addr = Emulator::new_empty().g2h(addr);
            copy_nonoverlapping(buf.as_ptr(), host_addr, buf.len());
        }
        // TODO use gdbstub's target_cpu_memory_rw_debug
        #[cfg(emulation_mode = "systemmode")]
        libafl_qemu_sys::cpu_memory_rw_debug(
            self.ptr,
            addr as GuestVirtAddr,
            buf.as_ptr() as *mut _,
            buf.len(),
            true,
        );
    }

    /// Read a value from a guest address.
    ///
    /// # Safety
    /// This will read from a translated guest address (using `g2h`).
    /// It just adds `guest_base` and writes to that location, without checking the bounds.
    /// This may only be safely used for valid guest addresses!
    pub unsafe fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) {
        #[cfg(emulation_mode = "usermode")]
        {
            let host_addr = Emulator::new_empty().g2h(addr);
            copy_nonoverlapping(host_addr, buf.as_mut_ptr(), buf.len());
        }
        // TODO use gdbstub's target_cpu_memory_rw_debug
        #[cfg(emulation_mode = "systemmode")]
        libafl_qemu_sys::cpu_memory_rw_debug(
            self.ptr,
            addr as GuestVirtAddr,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            false,
        );
    }

    #[must_use]
    pub fn num_regs(&self) -> i32 {
        unsafe { libafl_qemu_num_regs(self.ptr) }
    }

    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), String>
    where
        R: Into<i32>,
    {
        let reg = reg.into();
        let success = unsafe { libafl_qemu_write_reg(self.ptr, reg, addr_of!(val) as *const u8) };
        if success == 0 {
            Err(format!("Failed to write to register {reg}"))
        } else {
            Ok(())
        }
    }

    pub fn read_reg<R, T>(&self, reg: R) -> Result<T, String>
    where
        R: Into<i32>,
    {
        unsafe {
            let reg = reg.into();
            let mut val = MaybeUninit::uninit();
            let success = libafl_qemu_read_reg(self.ptr, reg, val.as_mut_ptr() as *mut u8);
            if success == 0 {
                Err(format!("Failed to read register {reg}"))
            } else {
                Ok(val.assume_init())
            }
        }
    }

    pub fn reset(&self) {
        unsafe { libafl_qemu_sys::cpu_reset(self.ptr) };
    }

    #[must_use]
    pub fn save_state(&self) -> CPUArchState {
        unsafe {
            let mut saved = MaybeUninit::<CPUArchState>::uninit();
            copy_nonoverlapping(self.ptr.as_mut().unwrap().env_ptr, saved.as_mut_ptr(), 1);
            saved.assume_init()
        }
    }

    pub fn restore_state(&self, saved: &CPUArchState) {
        unsafe {
            copy_nonoverlapping(saved, self.ptr.as_mut().unwrap().env_ptr, 1);
        }
    }

    #[must_use]
    pub fn raw_ptr(&self) -> CPUStatePtr {
        self.ptr
    }
}

static mut EMULATOR_IS_INITIALIZED: bool = false;

#[derive(Clone, Debug)]
pub struct Emulator {
    _private: (),
}

#[derive(Debug)]
pub enum EmuError {
    MultipleInstances,
    EmptyArgs,
    TooManyArgs(usize),
}

impl std::error::Error for EmuError {}

impl fmt::Display for EmuError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EmuError::MultipleInstances => {
                write!(f, "Only one instance of the QEMU Emulator is permitted")
            }
            EmuError::EmptyArgs => {
                write!(f, "QEMU emulator args cannot be empty")
            }
            EmuError::TooManyArgs(n) => {
                write!(
                    f,
                    "Too many arguments passed to QEMU emulator ({n} > i32::MAX)"
                )
            }
        }
    }
}

impl From<EmuError> for libafl::Error {
    fn from(err: EmuError) -> Self {
        libafl::Error::unknown(format!("{err}"))
    }
}

#[allow(clippy::unused_self)]
impl Emulator {
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn new(args: &[String], env: &[(String, String)]) -> Result<Emulator, EmuError> {
        unsafe {
            if EMULATOR_IS_INITIALIZED {
                return Err(EmuError::MultipleInstances);
            }
        }
        if args.is_empty() {
            return Err(EmuError::EmptyArgs);
        }

        let argc = args.len();
        if i32::try_from(argc).is_err() {
            return Err(EmuError::TooManyArgs(argc));
        }
        #[allow(clippy::cast_possible_wrap)]
        let argc = argc as i32;

        let args: Vec<String> = args.iter().map(|x| x.clone() + "\0").collect();
        let argv: Vec<*const u8> = args.iter().map(|x| x.as_bytes().as_ptr()).collect();
        let env_strs: Vec<String> = env
            .iter()
            .map(|(k, v)| format!("{}={}\0", &k, &v))
            .collect();
        let mut envp: Vec<*const u8> = env_strs.iter().map(|x| x.as_bytes().as_ptr()).collect();
        envp.push(null());
        unsafe {
            #[cfg(emulation_mode = "usermode")]
            qemu_user_init(
                argc,
                argv.as_ptr() as *const *const u8,
                envp.as_ptr() as *const *const u8,
            );
            #[cfg(emulation_mode = "systemmode")]
            {
                qemu_init(
                    argc,
                    argv.as_ptr() as *const *const u8,
                    envp.as_ptr() as *const *const u8,
                );
                libc::atexit(qemu_cleanup_atexit);
                libafl_qemu_sys::syx_snapshot_init();
            }
            EMULATOR_IS_INITIALIZED = true;
        }
        Ok(Emulator { _private: () })
    }

    #[must_use]
    pub(crate) fn new_empty() -> Emulator {
        Emulator { _private: () }
    }

    /// This function gets the memory mappings from the emulator.
    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn mappings(&self) -> GuestMaps {
        GuestMaps::new()
    }

    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    pub fn num_cpus(&self) -> usize {
        unsafe { libafl_qemu_num_cpus() as usize }
    }

    #[must_use]
    pub fn current_cpu(&self) -> Option<CPU> {
        let ptr = unsafe { libafl_qemu_current_cpu() };
        if ptr.is_null() {
            None
        } else {
            Some(CPU { ptr })
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub fn cpu_from_index(&self, index: usize) -> CPU {
        unsafe {
            CPU {
                ptr: libafl_qemu_get_cpu(index as i32),
            }
        }
    }

    #[must_use]
    pub fn page_from_addr(addr: GuestAddr) -> GuestAddr {
        unsafe { libafl_page_from_addr(addr) }
    }

    //#[must_use]
    /*pub fn page_size() -> GuestUsize {
        unsafe { libafl_page_size }
    }*/

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn g2h<T>(&self, addr: GuestAddr) -> *mut T {
        unsafe { (addr as usize + guest_base) as *mut T }
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn h2g<T>(&self, addr: *const T) -> GuestAddr {
        unsafe { (addr as usize - guest_base) as GuestAddr }
    }

    pub unsafe fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .write_mem(addr, buf);
    }

    pub unsafe fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .read_mem(addr, buf);
    }

    /// Write a value to a phsical guest address, including ROM areas.
    #[cfg(emulation_mode = "systemmode")]
    pub unsafe fn write_phys_mem(&self, paddr: GuestPhysAddr, buf: &[u8]) {
        libafl_qemu_sys::cpu_physical_memory_rw(
            paddr,
            buf.as_ptr() as *mut _,
            buf.len() as u64,
            true,
        );
    }

    /// Read a value from a physical guest address.
    #[cfg(emulation_mode = "systemmode")]
    pub unsafe fn read_phys_mem(&self, paddr: GuestPhysAddr, buf: &mut [u8]) {
        libafl_qemu_sys::cpu_physical_memory_rw(
            paddr,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u64,
            false,
        );
    }

    #[must_use]
    pub fn num_regs(&self) -> i32 {
        self.current_cpu().unwrap().num_regs()
    }

    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), String>
    where
        T: Num + PartialOrd + Copy,
        R: Into<i32>,
    {
        self.current_cpu().unwrap().write_reg(reg, val)
    }

    pub fn read_reg<R, T>(&self, reg: R) -> Result<T, String>
    where
        T: Num + PartialOrd + Copy,
        R: Into<i32>,
    {
        self.current_cpu().unwrap().read_reg(reg)
    }

    pub fn set_breakpoint(&self, addr: GuestAddr) {
        unsafe {
            libafl_qemu_set_breakpoint(addr.into());
        }
    }

    pub fn remove_breakpoint(&self, addr: GuestAddr) {
        unsafe {
            libafl_qemu_remove_breakpoint(addr.into());
        }
    }

    pub fn set_hook(
        &self,
        addr: GuestAddr,
        callback: extern "C" fn(GuestAddr, u64),
        data: u64,
        invalidate_block: bool,
    ) -> usize {
        unsafe { libafl_qemu_set_hook(addr.into(), callback, data, i32::from(invalidate_block)) }
    }

    #[must_use]
    pub fn remove_hook(&self, addr: GuestAddr, invalidate_block: bool) -> usize {
        unsafe { libafl_qemu_remove_hooks_at(addr.into(), i32::from(invalidate_block)) }
    }

    /// This function will run the emulator until the next breakpoint, or until finish.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run(&self) {
        #[cfg(emulation_mode = "usermode")]
        libafl_qemu_run();
        #[cfg(emulation_mode = "systemmode")]
        {
            vm_start();
            qemu_main_loop();
        }
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn binary_path<'a>(&self) -> &'a str {
        unsafe { from_utf8_unchecked(from_raw_parts(exec_path, strlen(exec_path))) }
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn load_addr(&self) -> GuestAddr {
        unsafe { libafl_load_addr() as GuestAddr }
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn get_brk(&self) -> GuestAddr {
        unsafe { libafl_get_brk() as GuestAddr }
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn set_brk(&self, brk: GuestAddr) {
        unsafe { libafl_set_brk(brk.into()) };
    }

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn get_mmap_start(&self) -> GuestAddr {
        unsafe { mmap_next_start }
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn set_mmap_start(&self, start: GuestAddr) {
        unsafe { mmap_next_start = start };
    }

    #[cfg(emulation_mode = "usermode")]
    #[allow(clippy::cast_sign_loss)]
    fn mmap(
        &self,
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

    #[cfg(emulation_mode = "usermode")]
    pub fn map_private(
        &self,
        addr: GuestAddr,
        size: usize,
        perms: MmapPerms,
    ) -> Result<GuestAddr, String> {
        self.mmap(addr, size, perms, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS)
            .map_err(|_| format!("Failed to map {addr}"))
            .map(|addr| addr as GuestAddr)
    }

    #[cfg(emulation_mode = "usermode")]
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
        .map_err(|_| format!("Failed to map {addr}"))
        .map(|addr| addr as GuestAddr)
    }

    #[cfg(emulation_mode = "usermode")]
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

    #[cfg(emulation_mode = "usermode")]
    pub fn unmap(&self, addr: GuestAddr, size: usize) -> Result<(), String> {
        if unsafe { libafl_qemu_sys::target_munmap(addr.into(), size as GuestUsize) } == 0 {
            Ok(())
        } else {
            Err(format!("Failed to unmap {addr}"))
        }
    }

    pub fn flush_jit(&self) {
        unsafe {
            libafl_flush_jit();
        }
    }

    pub fn add_edge_hooks(
        &self,
        gen: Option<extern "C" fn(GuestAddr, GuestAddr, u64) -> u64>,
        exec: Option<extern "C" fn(u64, u64)>,
        data: u64,
    ) {
        unsafe { libafl_add_edge_hook(gen, exec, data) }
    }

    pub fn add_block_hooks(
        &self,
        gen: Option<extern "C" fn(GuestAddr, u64) -> u64>,
        exec: Option<extern "C" fn(u64, u64)>,
        data: u64,
    ) {
        unsafe { libafl_add_block_hook(gen, exec, data) }
    }

    pub fn add_read_hooks(
        &self,
        gen: Option<extern "C" fn(GuestAddr, MemAccessInfo, u64) -> u64>,
        exec1: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec2: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec4: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec8: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec_n: Option<extern "C" fn(u64, GuestAddr, usize, u64)>,
        data: u64,
    ) {
        unsafe { libafl_add_read_hook(gen, exec1, exec2, exec4, exec8, exec_n, data) }
    }

    // TODO add MemOp info
    pub fn add_write_hooks(
        &self,
        gen: Option<extern "C" fn(GuestAddr, MemAccessInfo, u64) -> u64>,
        exec1: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec2: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec4: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec8: Option<extern "C" fn(u64, GuestAddr, u64)>,
        exec_n: Option<extern "C" fn(u64, GuestAddr, usize, u64)>,
        data: u64,
    ) {
        unsafe { libafl_add_write_hook(gen, exec1, exec2, exec4, exec8, exec_n, data) }
    }

    pub fn add_cmp_hooks(
        &self,
        gen: Option<extern "C" fn(GuestAddr, usize, u64) -> u64>,
        exec1: Option<extern "C" fn(u64, u8, u8, u64)>,
        exec2: Option<extern "C" fn(u64, u16, u16, u64)>,
        exec4: Option<extern "C" fn(u64, u32, u32, u64)>,
        exec8: Option<extern "C" fn(u64, u64, u64, u64)>,
        data: u64,
    ) {
        unsafe { libafl_add_cmp_hook(gen, exec1, exec2, exec4, exec8, data) }
    }

    pub fn add_backdoor_hook(&self, exec: extern "C" fn(GuestAddr, u64), data: u64) {
        unsafe { libafl_add_backdoor_hook(exec, data) };
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn set_on_thread_hook(&self, hook: extern "C" fn(tid: u32)) {
        unsafe {
            libafl_on_thread_hook = hook;
        }
    }

    #[cfg(emulation_mode = "systemmode")]
    pub fn save_snapshot(&self, name: &str, sync: bool) {
        let s = CString::new(name).expect("Invalid snapshot name");
        unsafe { libafl_save_qemu_snapshot(s.as_ptr() as *const _, sync) };
    }

    #[cfg(emulation_mode = "systemmode")]
    pub fn load_snapshot(&self, name: &str, sync: bool) {
        let s = CString::new(name).expect("Invalid snapshot name");
        unsafe { libafl_load_qemu_snapshot(s.as_ptr() as *const _, sync) };
    }

    #[cfg(emulation_mode = "systemmode")]
    #[must_use]
    pub fn create_fast_snapshot(&self, track: bool) -> FastSnapshot {
        unsafe { libafl_qemu_sys::syx_snapshot_create(track) }
    }

    #[cfg(emulation_mode = "systemmode")]
    pub fn restore_fast_snapshot(&self, snapshot: FastSnapshot) {
        unsafe { libafl_qemu_sys::syx_snapshot_root_restore(snapshot) }
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn set_pre_syscall_hook(
        &self,
        hook: extern "C" fn(i32, u64, u64, u64, u64, u64, u64, u64, u64) -> SyscallHookResult,
    ) {
        unsafe {
            libafl_pre_syscall_hook = hook;
        }
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn set_post_syscall_hook(
        &self,
        hook: extern "C" fn(u64, i32, u64, u64, u64, u64, u64, u64, u64, u64) -> u64,
    ) {
        unsafe {
            libafl_post_syscall_hook = hook;
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn add_gdb_cmd(&self, callback: Box<dyn FnMut(&Self, &str) -> bool>) {
        unsafe {
            GDB_COMMANDS.push(core::mem::transmute(callback));
            libafl_qemu_add_gdb_cmd(
                gdb_cmd,
                GDB_COMMANDS.last().unwrap() as *const _ as *const (),
            );
        }
    }

    pub fn gdb_reply(&self, output: &str) {
        unsafe { libafl_qemu_gdb_reply(output.as_bytes().as_ptr(), output.len()) };
    }
}

#[cfg(feature = "python")]
pub mod pybind {
    use std::convert::TryFrom;

    use pyo3::{exceptions::PyValueError, prelude::*, types::PyInt};

    use super::{GuestAddr, GuestUsize, MmapPerms, SyscallHookResult};

    static mut PY_SYSCALL_HOOK: Option<PyObject> = None;
    static mut PY_GENERIC_HOOKS: Vec<(GuestAddr, PyObject)> = vec![];

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

    extern "C" fn py_generic_hook_wrapper(_pc: GuestAddr, idx: u64) {
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
        fn new(args: Vec<String>, env: Vec<(String, String)>) -> PyResult<Emulator> {
            let emu = super::Emulator::new(&args, &env)
                .map_err(|e| PyValueError::new_err(format!("{e}")))?;
            Ok(Emulator { emu })
        }

        fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
            unsafe {
                self.emu.write_mem(addr, buf);
            }
        }

        fn read_mem(&self, addr: GuestAddr, size: usize) -> Vec<u8> {
            let mut buf = vec![0; size];
            unsafe {
                self.emu.read_mem(addr, &mut buf);
            }
            buf
        }

        fn num_regs(&self) -> i32 {
            self.emu.num_regs()
        }

        fn write_reg(&self, reg: i32, val: GuestUsize) -> PyResult<()> {
            self.emu.write_reg(reg, val).map_err(PyValueError::new_err)
        }

        fn read_reg(&self, reg: i32) -> PyResult<GuestUsize> {
            self.emu.read_reg(reg).map_err(PyValueError::new_err)
        }

        fn set_breakpoint(&self, addr: GuestAddr) {
            self.emu.set_breakpoint(addr);
        }

        fn remove_breakpoint(&self, addr: GuestAddr) {
            self.emu.remove_breakpoint(addr);
        }

        fn run(&self) {
            unsafe {
                self.emu.run();
            }
        }

        fn g2h(&self, addr: GuestAddr) -> u64 {
            self.emu.g2h::<*const u8>(addr) as u64
        }

        fn h2g(&self, addr: u64) -> GuestAddr {
            self.emu.h2g(addr as *const u8)
        }

        fn binary_path(&self) -> String {
            self.emu.binary_path().to_owned()
        }

        fn load_addr(&self) -> GuestAddr {
            self.emu.load_addr()
        }

        fn flush_jit(&self) {
            self.emu.flush_jit();
        }

        fn map_private(&self, addr: GuestAddr, size: usize, perms: i32) -> PyResult<GuestAddr> {
            if let Ok(p) = MmapPerms::try_from(perms) {
                self.emu
                    .map_private(addr, size, p)
                    .map_err(PyValueError::new_err)
            } else {
                Err(PyValueError::new_err("Invalid perms"))
            }
        }

        fn map_fixed(&self, addr: GuestAddr, size: usize, perms: i32) -> PyResult<GuestAddr> {
            if let Ok(p) = MmapPerms::try_from(perms) {
                self.emu
                    .map_fixed(addr, size, p)
                    .map_err(PyValueError::new_err)
            } else {
                Err(PyValueError::new_err("Invalid perms"))
            }
        }

        fn mprotect(&self, addr: GuestAddr, size: usize, perms: i32) -> PyResult<()> {
            if let Ok(p) = MmapPerms::try_from(perms) {
                self.emu
                    .mprotect(addr, size, p)
                    .map_err(PyValueError::new_err)
            } else {
                Err(PyValueError::new_err("Invalid perms"))
            }
        }

        fn unmap(&self, addr: GuestAddr, size: usize) -> PyResult<()> {
            self.emu.unmap(addr, size).map_err(PyValueError::new_err)
        }

        fn set_syscall_hook(&self, hook: PyObject) {
            unsafe {
                PY_SYSCALL_HOOK = Some(hook);
            }
            self.emu.set_pre_syscall_hook(py_syscall_hook_wrapper);
        }

        fn set_hook(&self, addr: GuestAddr, hook: PyObject) {
            unsafe {
                let idx = PY_GENERIC_HOOKS.len();
                PY_GENERIC_HOOKS.push((addr, hook));
                self.emu
                    .set_hook(addr, py_generic_hook_wrapper, idx as u64, true);
            }
        }

        fn remove_hook(&self, addr: GuestAddr) -> usize {
            unsafe {
                PY_GENERIC_HOOKS.retain(|(a, _)| *a != addr);
            }
            self.emu.remove_hook(addr, true)
        }
    }
}
