//! Expose QEMU user `LibAFL` C api to Rust

use core::{
    ffi::c_void,
    fmt,
    mem::{transmute, MaybeUninit},
    ptr::{addr_of, copy_nonoverlapping, null},
};
#[cfg(emulation_mode = "usermode")]
use std::cell::OnceCell;
#[cfg(emulation_mode = "systemmode")]
use std::{ffi::CStr, ptr::null_mut};
use std::{ffi::CString, ptr, slice::from_raw_parts, str::from_utf8_unchecked};

#[cfg(emulation_mode = "usermode")]
use libc::c_int;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use num_traits::Num;
use paste::paste;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{GuestReg, Regs};

/// Safe linking with of extern "C" functions.
/// This macro makes sure the declared symbol is defined *at link time*, avoiding declaring non-existant symbols
/// that could be silently ignored during linking if unused.
///
/// This macro relies on a nightly feature, and can only be used in this mode
/// It is (nearly) a drop-in replacement for extern "C" { } blocks containing function and static declarations, and will have the same effect in practice.
macro_rules! extern_c_checked {
    () => {};

    ($visibility:vis fn $c_fn:ident($($param_ident:ident : $param_ty:ty),*) $( -> $ret_ty:ty )?; $($tail:tt)*) =>  {
        paste! {
            #[cfg_attr(nightly, used(linker))]
            static [<__ $c_fn:upper __>]: unsafe extern "C" fn($($param_ty),*) $( -> $ret_ty )? = $c_fn;
        }

        extern "C" {
            $visibility fn $c_fn($($param_ident : $param_ty),*) $( -> $ret_ty )?;
        }

        extern_c_checked!($($tail)*);
    };

    ($visibility:vis static $c_var:ident : $c_var_ty:ty; $($tail:tt)*) => {
        paste! {
            #[allow(non_camel_case_types)]
            #[allow(unused)]
            struct [<__ $c_var:upper _STRUCT__>] { member: *const $c_var_ty }

            unsafe impl Sync for [<__ $c_var:upper _STRUCT__>] {}

            #[cfg_attr(nightly, used(linker))]
            static [<__ $c_var:upper __>]: [<__ $c_var:upper _STRUCT__>] = unsafe { [<__ $c_var:upper _STRUCT__>] { member: core::ptr::addr_of!($c_var) } };
        }

        extern "C" {
            $visibility static $c_var: $c_var_ty;
        }

        extern_c_checked!($($tail)*);
    };

    ($visibility:vis static mut $c_var:ident : $c_var_ty:ty; $($tail:tt)*) => {
        paste! {
            #[allow(non_camel_case_types)]
            #[allow(unused)]
            struct [<__ $c_var:upper _STRUCT__>] { member: *const $c_var_ty }

            unsafe impl Sync for [<__ $c_var:upper _STRUCT__>] {}

            #[cfg_attr(nightly, used(linker))]
            static mut [<__ $c_var:upper __>]: [<__ $c_var:upper _STRUCT__>] = unsafe { [<__ $c_var:upper _STRUCT__>] { member: core::ptr::addr_of!($c_var) } };
        }

        extern "C" {
            $visibility static mut $c_var: $c_var_ty;
        }

        extern_c_checked!($($tail)*);
    };
}

pub type GuestAddr = libafl_qemu_sys::target_ulong;
pub type GuestUsize = libafl_qemu_sys::target_ulong;
pub type GuestIsize = libafl_qemu_sys::target_long;
pub type GuestVirtAddr = libafl_qemu_sys::vaddr;
pub type GuestPhysAddr = libafl_qemu_sys::hwaddr;

pub type GuestHwAddrInfo = libafl_qemu_sys::qemu_plugin_hwaddr;

#[derive(Debug, Clone)]
pub enum GuestAddrKind {
    Physical(GuestPhysAddr),
    Virtual(GuestVirtAddr),
}

impl fmt::Display for GuestAddrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestAddrKind::Physical(phys_addr) => write!(f, "hwaddr 0x{phys_addr:x}"),
            GuestAddrKind::Virtual(virt_addr) => write!(f, "vaddr 0x{virt_addr:x}"),
        }
    }
}

#[cfg(emulation_mode = "systemmode")]
pub type FastSnapshot = *mut libafl_qemu_sys::SyxSnapshot;

#[cfg(emulation_mode = "systemmode")]
pub enum DeviceSnapshotFilter {
    All,
    AllowList(Vec<String>),
    DenyList(Vec<String>),
}

#[cfg(emulation_mode = "systemmode")]
impl DeviceSnapshotFilter {
    fn enum_id(&self) -> libafl_qemu_sys::DeviceSnapshotKind {
        match self {
            DeviceSnapshotFilter::All => libafl_qemu_sys::DeviceSnapshotKind_DEVICE_SNAPSHOT_ALL,
            DeviceSnapshotFilter::AllowList(_) => {
                libafl_qemu_sys::DeviceSnapshotKind_DEVICE_SNAPSHOT_ALLOWLIST
            }
            DeviceSnapshotFilter::DenyList(_) => {
                libafl_qemu_sys::DeviceSnapshotKind_DEVICE_SNAPSHOT_DENYLIST
            }
        }
    }

    fn devices(&self, v: &mut Vec<*mut i8>) -> *mut *mut i8 {
        v.clear();
        match self {
            DeviceSnapshotFilter::All => null_mut(),
            DeviceSnapshotFilter::AllowList(l) | DeviceSnapshotFilter::DenyList(l) => {
                for name in l {
                    v.push(name.as_bytes().as_ptr() as *mut i8);
                }
                v.as_mut_ptr()
            }
        }
    }
}

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

use crate::sync_backdoor::{SyncBackdoor, SyncBackdoorError};

pub type CPUStatePtr = *mut libafl_qemu_sys::CPUState;
pub type CPUArchStatePtr = *mut libafl_qemu_sys::CPUArchState;

pub type ExitReasonPtr = *mut libafl_qemu_sys::libafl_exit_reason;

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

#[cfg(emulation_mode = "usermode")]
#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter, PartialEq, Eq)]
#[repr(i32)]
pub enum VerifyAccess {
    Read = libc::PROT_READ,
    Write = libc::PROT_READ | libc::PROT_WRITE,
}

// syshook_ret
#[repr(C)]
#[cfg_attr(feature = "python", pyclass)]
#[cfg_attr(feature = "python", derive(FromPyObject))]
pub struct SyscallHookResult {
    pub retval: GuestAddr,
    pub skip_syscall: bool,
}

#[cfg(feature = "python")]
#[pymethods]
impl SyscallHookResult {
    #[new]
    #[must_use]
    pub fn new(value: Option<GuestAddr>) -> Self {
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
    pub fn new(value: Option<GuestAddr>) -> Self {
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
extern_c_checked! {
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

    static mut libafl_dump_core_hook: unsafe extern "C" fn(i32);
    static mut libafl_force_dfl: i32;
}

#[cfg(emulation_mode = "systemmode")]
extern_c_checked! {
    fn qemu_init(argc: i32, argv: *const *const u8, envp: *const *const u8);

    fn vm_start();
    fn qemu_main_loop();
    fn qemu_cleanup();

    fn libafl_save_qemu_snapshot(name: *const u8, sync: bool);
    fn libafl_load_qemu_snapshot(name: *const u8, sync: bool);

    fn libafl_qemu_current_paging_id(cpu: CPUStatePtr) -> GuestPhysAddr;
}

#[cfg(emulation_mode = "systemmode")]
extern "C" fn qemu_cleanup_atexit() {
    unsafe {
        qemu_cleanup();
    }
}

// TODO rely completely on libafl_qemu_sys
extern_c_checked! {
    //static libafl_page_size: GuestUsize;
    fn libafl_page_from_addr(addr: GuestAddr) -> GuestAddr;

    // CPUState* libafl_qemu_get_cpu(int cpu_index);
    fn libafl_qemu_get_cpu(cpu_index: i32) -> CPUStatePtr;
    // int libafl_qemu_num_cpus(void);
    fn libafl_qemu_num_cpus() -> i32;
    // CPUState* libafl_qemu_current_cpu(void);
    fn libafl_qemu_current_cpu() -> CPUStatePtr;

    // struct libafl_exit_reason* libafl_get_exit_reason(void);
    fn libafl_get_exit_reason() -> ExitReasonPtr;

    fn libafl_qemu_cpu_index(cpu: CPUStatePtr) -> i32;

    fn libafl_qemu_write_reg(cpu: CPUStatePtr, reg: i32, val: *const u8) -> i32;
    fn libafl_qemu_read_reg(cpu: CPUStatePtr, reg: i32, val: *mut u8) -> i32;
    fn libafl_qemu_num_regs(cpu: CPUStatePtr) -> i32;

    fn libafl_qemu_set_breakpoint(addr: u64) -> i32;
    fn libafl_qemu_remove_breakpoint(addr: u64) -> i32;
    fn libafl_flush_jit();
    fn libafl_qemu_trigger_breakpoint(cpu: CPUStatePtr);

    fn strlen(s: *const u8) -> usize;

    fn libafl_qemu_add_gdb_cmd(
        callback: extern "C" fn(*const (), *const u8, usize) -> i32,
        data: *const ()
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

#[allow(clippy::vec_box)]
static mut GDB_COMMANDS: Vec<Box<FatPtr>> = vec![];

extern "C" fn gdb_cmd(data: *const (), buf: *const u8, len: usize) -> i32 {
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

#[derive(Debug, PartialEq)]
pub enum CallingConvention {
    Cdecl,
}

pub trait ArchExtras {
    fn read_return_address<T>(&self) -> Result<T, String>
    where
        T: From<GuestReg>;
    fn write_return_address<T>(&self, val: T) -> Result<(), String>
    where
        T: Into<GuestReg>;
    fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, String>
    where
        T: From<GuestReg>;
    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), String>
    where
        T: Into<GuestReg>;
}

#[allow(clippy::unused_self)]
impl CPU {
    #[must_use]
    pub fn emulator(&self) -> Emulator {
        unsafe { Emulator::new_empty() }
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

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn access_ok(&self, kind: VerifyAccess, addr: GuestAddr, size: usize) -> bool {
        unsafe {
            // TODO add support for tagged GuestAddr
            libafl_qemu_sys::page_check_range(addr, size as GuestAddr, kind.into())
        }
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

    #[cfg(emulation_mode = "systemmode")]
    #[must_use]
    pub fn get_current_paging_id(&self) -> Option<GuestPhysAddr> {
        let paging_id = unsafe { libafl_qemu_current_paging_id(self.ptr) };

        if paging_id == 0 {
            None
        } else {
            Some(paging_id)
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
        T: Into<GuestReg>,
    {
        let reg = reg.into();
        #[cfg(feature = "be")]
        let val = GuestReg::to_be(val.into());

        #[cfg(not(feature = "be"))]
        let val = GuestReg::to_le(val.into());

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
        T: From<GuestReg>,
    {
        unsafe {
            let reg = reg.into();
            let mut val = MaybeUninit::uninit();
            let success = libafl_qemu_read_reg(self.ptr, reg, val.as_mut_ptr() as *mut u8);
            if success == 0 {
                Err(format!("Failed to read register {reg}"))
            } else {
                #[cfg(feature = "be")]
                return Ok(GuestReg::from_be(val.assume_init()).into());

                #[cfg(not(feature = "be"))]
                return Ok(GuestReg::from_le(val.assume_init()).into());
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
            copy_nonoverlapping(
                libafl_qemu_sys::cpu_env(self.ptr.as_mut().unwrap()),
                saved.as_mut_ptr(),
                1,
            );
            saved.assume_init()
        }
    }

    pub fn restore_state(&self, saved: &CPUArchState) {
        unsafe {
            copy_nonoverlapping(
                saved,
                libafl_qemu_sys::cpu_env(self.ptr.as_mut().unwrap()),
                1,
            );
        }
    }

    #[must_use]
    pub fn raw_ptr(&self) -> CPUStatePtr {
        self.ptr
    }

    #[must_use]
    pub fn page_size(&self) -> usize {
        #[cfg(emulation_mode = "usermode")]
        {
            thread_local! {
                static PAGE_SIZE: OnceCell<usize> = const { OnceCell::new() };
            }

            PAGE_SIZE.with(|s| {
                *s.get_or_init(|| {
                    unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) }
                        .try_into()
                        .expect("Invalid page size")
                })
            })
        }
        #[cfg(emulation_mode = "systemmode")]
        {
            unsafe { libafl_qemu_sys::qemu_target_page_size() }
        }
    }

    #[must_use]
    pub fn display_context(&self) -> String {
        let mut display = String::new();
        let mut maxl = 0;
        for r in Regs::iter() {
            maxl = std::cmp::max(format!("{r:#?}").len(), maxl);
        }
        for (i, r) in Regs::iter().enumerate() {
            let v: GuestAddr = self.read_reg(r).unwrap();
            let sr = format!("{r:#?}");
            display += &format!("{sr:>maxl$}: {v:#016x} ");
            if (i + 1) % 4 == 0 {
                display += "\n";
            }
        }
        if !display.ends_with('\n') {
            display += "\n";
        }
        display
    }
}

pub trait HookId {
    fn remove(&self, invalidate_block: bool) -> bool;
}

macro_rules! create_hook_id {
    ($name:ident, $sys:ident, true) => {
        paste::paste! {
            #[derive(Clone, Copy, PartialEq, Debug)]
            pub struct [<$name HookId>](pub(crate) usize);
            impl HookId for [<$name HookId>] {
                fn remove(&self, invalidate_block: bool) -> bool {
                    unsafe { libafl_qemu_sys::$sys(self.0, invalidate_block.into()) != 0 }
                }
            }
        }
    };
    ($name:ident, $sys:ident, false) => {
        paste::paste! {
            #[derive(Clone, Copy, PartialEq, Debug)]
            pub struct [<$name HookId>](pub(crate) usize);
            impl HookId for [<$name HookId>] {
                fn remove(&self, _invalidate_block: bool) -> bool {
                    unsafe { libafl_qemu_sys::$sys(self.0) != 0 }
                }
            }
        }
    };
}

create_hook_id!(Instruction, libafl_qemu_remove_hook, true);
create_hook_id!(Backdoor, libafl_qemu_remove_backdoor_hook, true);
create_hook_id!(Edge, libafl_qemu_remove_edge_hook, true);
create_hook_id!(Block, libafl_qemu_remove_block_hook, true);
create_hook_id!(Read, libafl_qemu_remove_read_hook, true);
create_hook_id!(Write, libafl_qemu_remove_write_hook, true);
create_hook_id!(Cmp, libafl_qemu_remove_cmp_hook, true);
create_hook_id!(PreSyscall, libafl_qemu_remove_pre_syscall_hook, false);
create_hook_id!(PostSyscall, libafl_qemu_remove_post_syscall_hook, false);
create_hook_id!(NewThread, libafl_qemu_remove_new_thread_hook, false);

use std::pin::Pin;

#[derive(Debug)]
pub struct HookData(u64);

impl<T> From<Pin<&mut T>> for HookData {
    fn from(value: Pin<&mut T>) -> Self {
        unsafe { HookData(core::mem::transmute(value)) }
    }
}

impl<T> From<Pin<&T>> for HookData {
    fn from(value: Pin<&T>) -> Self {
        unsafe { HookData(core::mem::transmute(value)) }
    }
}

impl<T> From<&'static mut T> for HookData {
    fn from(value: &'static mut T) -> Self {
        unsafe { HookData(core::mem::transmute(value)) }
    }
}

impl<T> From<&'static T> for HookData {
    fn from(value: &'static T) -> Self {
        unsafe { HookData(core::mem::transmute(value)) }
    }
}

impl<T> From<*mut T> for HookData {
    fn from(value: *mut T) -> Self {
        HookData(value as u64)
    }
}

impl<T> From<*const T> for HookData {
    fn from(value: *const T) -> Self {
        HookData(value as u64)
    }
}

impl From<u64> for HookData {
    fn from(value: u64) -> Self {
        HookData(value)
    }
}

impl From<u32> for HookData {
    fn from(value: u32) -> Self {
        HookData(u64::from(value))
    }
}

impl From<u16> for HookData {
    fn from(value: u16) -> Self {
        HookData(u64::from(value))
    }
}

impl From<u8> for HookData {
    fn from(value: u8) -> Self {
        HookData(u64::from(value))
    }
}

#[derive(Debug)]
pub enum EmuError {
    MultipleInstances,
    EmptyArgs,
    TooManyArgs(usize),
}

#[derive(Debug, Clone)]
pub enum EmuExitReason {
    End,                        // QEMU ended for some reason.
    Breakpoint(GuestVirtAddr), // Breakpoint triggered. Contains the virtual address of the trigger.
    SyncBackdoor(SyncBackdoor), // Synchronous backdoor: The guest triggered a backdoor and should return to LibAFL.
}

impl fmt::Display for EmuExitReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EmuExitReason::End => write!(f, "End"),
            EmuExitReason::Breakpoint(vaddr) => write!(f, "Breakpoint @vaddr 0x{vaddr:x}"),
            EmuExitReason::SyncBackdoor(sync_backdoor) => {
                write!(f, "Sync backdoor exit: {sync_backdoor}")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum EmuExitReasonError {
    UnknownKind(),
    UnexpectedExit,
    SyncBackdoorError(SyncBackdoorError),
}

impl From<SyncBackdoorError> for EmuExitReasonError {
    fn from(sync_backdoor_error: SyncBackdoorError) -> Self {
        EmuExitReasonError::SyncBackdoorError(sync_backdoor_error)
    }
}

impl TryFrom<&Emulator> for EmuExitReason {
    type Error = EmuExitReasonError;
    fn try_from(emu: &Emulator) -> Result<Self, Self::Error> {
        let exit_reason = unsafe { libafl_get_exit_reason() };
        if exit_reason.is_null() {
            Err(EmuExitReasonError::UnexpectedExit)
        } else {
            let exit_reason: &mut libafl_qemu_sys::libafl_exit_reason =
                unsafe { transmute(&mut *exit_reason) };
            Ok(match exit_reason.kind {
                libafl_qemu_sys::libafl_exit_reason_kind_BREAKPOINT => unsafe {
                    EmuExitReason::Breakpoint(exit_reason.data.breakpoint.addr.into())
                },
                libafl_qemu_sys::libafl_exit_reason_kind_SYNC_BACKDOOR => {
                    EmuExitReason::SyncBackdoor(emu.try_into()?)
                }
                _ => return Err(EmuExitReasonError::UnknownKind()),
            })
        }
    }
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

static mut EMULATOR_IS_INITIALIZED: bool = false;

#[derive(Clone, Debug)]
pub struct Emulator {
    _private: (),
}

#[allow(clippy::unused_self)]
impl Emulator {
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn new(args: &[String], env: &[(String, String)]) -> Result<Emulator, EmuError> {
        if args.is_empty() {
            return Err(EmuError::EmptyArgs);
        }

        let argc = args.len();
        if i32::try_from(argc).is_err() {
            return Err(EmuError::TooManyArgs(argc));
        }

        unsafe {
            if EMULATOR_IS_INITIALIZED {
                return Err(EmuError::MultipleInstances);
            }
            EMULATOR_IS_INITIALIZED = true;
        }

        #[allow(clippy::cast_possible_wrap)]
        let argc = argc as i32;

        let args: Vec<CString> = args
            .iter()
            .map(|x| CString::new(x.clone()).unwrap())
            .collect();
        let mut argv: Vec<*const u8> = args.iter().map(|x| x.as_ptr() as *const u8).collect();
        argv.push(ptr::null()); // argv is always null terminated.
        let env_strs: Vec<String> = env
            .iter()
            .map(|(k, v)| format!("{}={}\0", &k, &v))
            .collect();
        let mut envp: Vec<*const u8> = env_strs.iter().map(|x| x.as_bytes().as_ptr()).collect();
        envp.push(null());
        unsafe {
            #[cfg(emulation_mode = "usermode")]
            qemu_user_init(argc, argv.as_ptr(), envp.as_ptr());
            #[cfg(emulation_mode = "systemmode")]
            {
                qemu_init(
                    argc,
                    argv.as_ptr() as *const *const u8,
                    envp.as_ptr() as *const *const u8,
                );
                libc::atexit(qemu_cleanup_atexit);
                libafl_qemu_sys::syx_snapshot_init(true);
            }
        }
        Ok(Emulator { _private: () })
    }

    #[must_use]
    pub fn get() -> Option<Self> {
        unsafe {
            if EMULATOR_IS_INITIALIZED {
                Some(Self::new_empty())
            } else {
                None
            }
        }
    }

    /// Get an empty emulator.
    ///
    /// # Safety
    ///
    /// Should not be used if `Emulator::new` has never been used before (otherwise QEMU will not be initialized).
    /// Prefer `Emulator::get` for a safe version of this method.
    #[must_use]
    pub unsafe fn new_empty() -> Emulator {
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

    #[cfg(emulation_mode = "usermode")]
    #[must_use]
    pub fn access_ok(&self, kind: VerifyAccess, addr: GuestAddr, size: usize) -> bool {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .access_ok(kind, addr, size)
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
        T: Num + PartialOrd + Copy + Into<GuestReg>,
        R: Into<i32>,
    {
        self.current_cpu().unwrap().write_reg(reg, val)
    }

    pub fn read_reg<R, T>(&self, reg: R) -> Result<T, String>
    where
        T: Num + PartialOrd + Copy + From<GuestReg>,
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

    pub fn entry_break(&self, addr: GuestAddr) {
        self.set_breakpoint(addr);
        unsafe {
            // TODO: decide what to do with sync exit here: ignore or check for bp exit?
            let _ = self.run();
        }
        self.remove_breakpoint(addr);
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn force_dfl(&self) {
        unsafe {
            libafl_force_dfl = 1;
        }
    }
    /// This function will run the emulator until the next breakpoint, or until finish.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run(&self) -> Result<EmuExitReason, EmuExitReasonError> {
        #[cfg(emulation_mode = "usermode")]
        libafl_qemu_run();
        #[cfg(emulation_mode = "systemmode")]
        {
            vm_start();
            qemu_main_loop();
        }
        EmuExitReason::try_from(self)
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
            .map_err(|()| format!("Failed to map {addr}"))
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
        .map_err(|()| format!("Failed to map {addr}"))
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

    // TODO set T lifetime to be like Emulator
    pub fn set_hook<T: Into<HookData>>(
        &self,
        data: T,
        addr: GuestAddr,
        callback: extern "C" fn(T, GuestAddr),
        invalidate_block: bool,
    ) -> InstructionHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, GuestAddr) = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_qemu_set_hook(
                addr.into(),
                Some(callback),
                data,
                i32::from(invalidate_block),
            );
            InstructionHookId(num)
        }
    }

    #[must_use]
    pub fn remove_hook(&self, id: impl HookId, invalidate_block: bool) -> bool {
        id.remove(invalidate_block)
    }

    #[must_use]
    pub fn remove_hooks_at(&self, addr: GuestAddr, invalidate_block: bool) -> usize {
        unsafe {
            libafl_qemu_sys::libafl_qemu_remove_hooks_at(addr.into(), i32::from(invalidate_block))
        }
    }

    pub fn add_edge_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr, GuestAddr) -> u64>,
        exec: Option<extern "C" fn(T, u64)>,
    ) -> EdgeHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<extern "C" fn(u64, GuestAddr, GuestAddr) -> u64> =
                core::mem::transmute(gen);
            let exec: Option<extern "C" fn(u64, u64)> = core::mem::transmute(exec);
            let num = libafl_qemu_sys::libafl_add_edge_hook(gen, exec, data);
            EdgeHookId(num)
        }
    }

    pub fn add_block_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr) -> u64>,
        post_gen: Option<extern "C" fn(T, GuestAddr, GuestUsize)>,
        exec: Option<extern "C" fn(T, u64)>,
    ) -> BlockHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<extern "C" fn(u64, GuestAddr) -> u64> = core::mem::transmute(gen);
            let post_gen: Option<extern "C" fn(u64, GuestAddr, GuestUsize)> =
                core::mem::transmute(post_gen);
            let exec: Option<extern "C" fn(u64, u64)> = core::mem::transmute(exec);
            let num = libafl_qemu_sys::libafl_add_block_hook(gen, post_gen, exec, data);
            BlockHookId(num)
        }
    }

    pub fn add_read_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr, MemAccessInfo) -> u64>,
        exec1: Option<extern "C" fn(T, u64, GuestAddr)>,
        exec2: Option<extern "C" fn(T, u64, GuestAddr)>,
        exec4: Option<extern "C" fn(T, u64, GuestAddr)>,
        exec8: Option<extern "C" fn(T, u64, GuestAddr)>,
        exec_n: Option<extern "C" fn(T, u64, GuestAddr, usize)>,
    ) -> ReadHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<extern "C" fn(u64, GuestAddr, libafl_qemu_sys::MemOpIdx) -> u64> =
                core::mem::transmute(gen);
            let exec1: Option<extern "C" fn(u64, u64, GuestAddr)> = core::mem::transmute(exec1);
            let exec2: Option<extern "C" fn(u64, u64, GuestAddr)> = core::mem::transmute(exec2);
            let exec4: Option<extern "C" fn(u64, u64, GuestAddr)> = core::mem::transmute(exec4);
            let exec8: Option<extern "C" fn(u64, u64, GuestAddr)> = core::mem::transmute(exec8);
            let exec_n: Option<extern "C" fn(u64, u64, GuestAddr, usize)> =
                core::mem::transmute(exec_n);
            let num = libafl_qemu_sys::libafl_add_read_hook(
                gen, exec1, exec2, exec4, exec8, exec_n, data,
            );
            ReadHookId(num)
        }
    }

    // TODO add MemOp info
    pub fn add_write_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr, MemAccessInfo) -> u64>,
        exec1: Option<extern "C" fn(T, u64, GuestAddr)>,
        exec2: Option<extern "C" fn(T, u64, GuestAddr)>,
        exec4: Option<extern "C" fn(T, u64, GuestAddr)>,
        exec8: Option<extern "C" fn(T, u64, GuestAddr)>,
        exec_n: Option<extern "C" fn(T, u64, GuestAddr, usize)>,
    ) -> WriteHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<extern "C" fn(u64, GuestAddr, libafl_qemu_sys::MemOpIdx) -> u64> =
                core::mem::transmute(gen);
            let exec1: Option<extern "C" fn(u64, u64, GuestAddr)> = core::mem::transmute(exec1);
            let exec2: Option<extern "C" fn(u64, u64, GuestAddr)> = core::mem::transmute(exec2);
            let exec4: Option<extern "C" fn(u64, u64, GuestAddr)> = core::mem::transmute(exec4);
            let exec8: Option<extern "C" fn(u64, u64, GuestAddr)> = core::mem::transmute(exec8);
            let exec_n: Option<extern "C" fn(u64, u64, GuestAddr, usize)> =
                core::mem::transmute(exec_n);
            let num = libafl_qemu_sys::libafl_add_write_hook(
                gen, exec1, exec2, exec4, exec8, exec_n, data,
            );
            WriteHookId(num)
        }
    }

    pub fn add_cmp_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr, usize) -> u64>,
        exec1: Option<extern "C" fn(T, u64, u8, u8)>,
        exec2: Option<extern "C" fn(T, u64, u16, u16)>,
        exec4: Option<extern "C" fn(T, u64, u32, u32)>,
        exec8: Option<extern "C" fn(T, u64, u64, u64)>,
    ) -> CmpHookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<extern "C" fn(u64, GuestAddr, usize) -> u64> =
                core::mem::transmute(gen);
            let exec1: Option<extern "C" fn(u64, u64, u8, u8)> = core::mem::transmute(exec1);
            let exec2: Option<extern "C" fn(u64, u64, u16, u16)> = core::mem::transmute(exec2);
            let exec4: Option<extern "C" fn(u64, u64, u32, u32)> = core::mem::transmute(exec4);
            let exec8: Option<extern "C" fn(u64, u64, u64, u64)> = core::mem::transmute(exec8);
            let num = libafl_qemu_sys::libafl_add_cmp_hook(gen, exec1, exec2, exec4, exec8, data);
            CmpHookId(num)
        }
    }

    pub fn add_backdoor_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, GuestAddr),
    ) -> BackdoorHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, GuestAddr) = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_add_backdoor_hook(Some(callback), data);
            BackdoorHookId(num)
        }
    }

    #[cfg(emulation_mode = "usermode")]
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
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(
                u64,
                i32,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
                GuestAddr,
            ) -> libafl_qemu_sys::syshook_ret = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_add_pre_syscall_hook(Some(callback), data);
            PreSyscallHookId(num)
        }
    }

    #[cfg(emulation_mode = "usermode")]
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
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(
                u64,
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
            ) -> GuestAddr = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_add_post_syscall_hook(Some(callback), data);
            PostSyscallHookId(num)
        }
    }

    #[cfg(emulation_mode = "usermode")]
    pub fn add_new_thread_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, tid: u32) -> bool,
    ) -> NewThreadHookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, u32) -> bool = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_add_new_thread_hook(Some(callback), data);
            NewThreadHookId(num)
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
        unsafe {
            libafl_qemu_sys::syx_snapshot_new(
                track,
                true,
                libafl_qemu_sys::DeviceSnapshotKind_DEVICE_SNAPSHOT_ALL,
                null_mut(),
            )
        }
    }

    #[cfg(emulation_mode = "systemmode")]
    #[must_use]
    pub fn create_fast_snapshot_filter(
        &self,
        track: bool,
        device_filter: &DeviceSnapshotFilter,
    ) -> FastSnapshot {
        let mut v = vec![];
        unsafe {
            libafl_qemu_sys::syx_snapshot_new(
                track,
                true,
                device_filter.enum_id(),
                device_filter.devices(&mut v),
            )
        }
    }

    #[cfg(emulation_mode = "systemmode")]
    pub fn restore_fast_snapshot(&self, snapshot: FastSnapshot) {
        unsafe { libafl_qemu_sys::syx_snapshot_root_restore(snapshot) }
    }

    #[cfg(emulation_mode = "systemmode")]
    pub fn list_devices(&self) -> Vec<String> {
        let mut r = vec![];
        unsafe {
            let devices = libafl_qemu_sys::device_list_all();
            if devices.is_null() {
                return r;
            }

            let mut ptr = devices;
            while !(*ptr).is_null() {
                let c_str: &CStr = CStr::from_ptr(*ptr);
                let name = c_str.to_str().unwrap().to_string();
                r.push(name);

                ptr = ptr.add(1);
            }

            libc::free(devices as *mut c_void);
            r
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn add_gdb_cmd(&self, callback: Box<dyn FnMut(&Self, &str) -> bool>) {
        unsafe {
            let fat: Box<FatPtr> = Box::new(transmute(callback));
            libafl_qemu_add_gdb_cmd(gdb_cmd, core::ptr::from_ref(&*fat) as *const ());
            GDB_COMMANDS.push(fat);
        }
    }

    pub fn gdb_reply(&self, output: &str) {
        unsafe { libafl_qemu_gdb_reply(output.as_bytes().as_ptr(), output.len()) };
    }

    #[cfg(emulation_mode = "usermode")]
    #[allow(clippy::type_complexity)]
    pub fn set_crash_hook(&self, callback: extern "C" fn(i32)) {
        unsafe {
            libafl_dump_core_hook = callback;
        }
    }
}

impl ArchExtras for Emulator {
    fn read_return_address<T>(&self) -> Result<T, String>
    where
        T: From<GuestReg>,
    {
        self.current_cpu()
            .ok_or("Failed to get current CPU")?
            .read_return_address::<T>()
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), String>
    where
        T: Into<GuestReg>,
    {
        self.current_cpu()
            .ok_or("Failed to get current CPU")?
            .write_return_address::<T>(val)
    }

    fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, String>
    where
        T: From<GuestReg>,
    {
        self.current_cpu()
            .ok_or("Failed to get current CPU")?
            .read_function_argument::<T>(conv, idx)
    }

    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), String>
    where
        T: Into<GuestReg>,
    {
        self.current_cpu()
            .ok_or("Failed to get current CPU")?
            .write_function_argument::<T>(conv, idx, val)
    }
}

#[cfg(feature = "python")]
pub mod pybind {
    use pyo3::{exceptions::PyValueError, prelude::*, types::PyInt};

    use super::{GuestAddr, GuestUsize, MmapPerms, SyscallHookResult};

    static mut PY_SYSCALL_HOOK: Option<PyObject> = None;
    static mut PY_GENERIC_HOOKS: Vec<(GuestAddr, PyObject)> = vec![];

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

    extern "C" fn py_generic_hook_wrapper(idx: u64, _pc: GuestAddr) {
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

        fn entry_break(&self, addr: GuestAddr) {
            self.emu.entry_break(addr);
        }

        fn remove_breakpoint(&self, addr: GuestAddr) {
            self.emu.remove_breakpoint(addr);
        }

        fn run(&self) {
            unsafe {
                self.emu.run().unwrap();
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
            self.emu.add_pre_syscall_hook(0u64, py_syscall_hook_wrapper);
        }

        fn set_hook(&self, addr: GuestAddr, hook: PyObject) {
            unsafe {
                let idx = PY_GENERIC_HOOKS.len();
                PY_GENERIC_HOOKS.push((addr, hook));
                self.emu
                    .set_hook(idx as u64, addr, py_generic_hook_wrapper, true);
            }
        }

        fn remove_hooks_at(&self, addr: GuestAddr) -> usize {
            unsafe {
                PY_GENERIC_HOOKS.retain(|(a, _)| *a != addr);
            }
            self.emu.remove_hooks_at(addr, true)
        }
    }
}
