//! Expose QEMU user `LibAFL` C api to Rust

use core::{
    convert::Into,
    ffi::c_void,
    fmt,
    mem::{transmute, MaybeUninit},
    ptr::{addr_of, copy_nonoverlapping, null},
};
use std::{
    cell::RefCell,
    collections::HashSet,
    ffi::CString,
    fmt::{Debug, Display, Formatter},
    ptr,
    slice::from_raw_parts,
    str::from_utf8_unchecked,
};

use libafl::{executors::ExitKind, inputs::BytesInput};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use num_traits::Num;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::{GuestReg, Regs};

#[cfg(emulation_mode = "systemmode")]
pub mod systemmode;
#[cfg(emulation_mode = "systemmode")]
pub use systemmode::*;

#[cfg(emulation_mode = "usermode")]
pub mod usermode;
#[cfg(emulation_mode = "usermode")]
pub use usermode::*;

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

#[derive(Debug, Clone)]
pub enum QemuShutdownCause {
    None,
    HostError,
    HostQmpQuit,
    HostQmpSystemReset,
    HostSignal(Signal),
    HostUi,
    GuestShutdown,
    GuestReset,
    GuestPanic,
    SubsystemReset,
    SnapshotLoad,
}

impl fmt::Display for GuestAddrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestAddrKind::Physical(phys_addr) => write!(f, "hwaddr 0x{phys_addr:x}"),
            GuestAddrKind::Virtual(virt_addr) => write!(f, "vaddr 0x{virt_addr:x}"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Command {
    Save,
    Load,
    Input(CommandInput),
    Start(CommandInput),
    Exit(Option<ExitKind>),
    Version(u64),
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Save => write!(f, "Save VM"),
            Command::Load => write!(f, "Reload VM"),
            Command::Input(command_input) => write!(f, "Set fuzzing input @{command_input}"),
            Command::Start(command_input) => {
                write!(f, "Start fuzzing with input @{command_input}")
            }
            Command::Exit(exit_kind) => write!(f, "Exit of kind {exit_kind:?}"),
            Command::Version(version) => write!(f, "Client version: {version}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandInput {
    addr: GuestAddrKind,
    max_input_size: GuestReg,
    cpu: Option<CPU>,
}

impl CommandInput {
    pub fn phys(addr: GuestPhysAddr, max_input_size: GuestReg, cpu: Option<CPU>) -> Self {
        Self {
            addr: GuestAddrKind::Physical(addr),
            max_input_size,
            cpu,
        }
    }

    pub fn virt(addr: GuestVirtAddr, max_input_size: GuestReg, cpu: CPU) -> Self {
        Self {
            addr: GuestAddrKind::Virtual(addr),
            max_input_size,
            cpu: Some(cpu),
        }
    }

    pub fn exec<E>(&self, emu: &Emulator<E>, backdoor: Option<&SyncExit>, input: &[u8])
    where
        E: IsEmuExitHandler,
    {
        let max_len: usize = self.max_input_size.try_into().unwrap();

        let input_sliced;
        if input.len() > max_len {
            input_sliced = &input[0..max_len];
        } else {
            input_sliced = input;
        }

        match self.addr {
            GuestAddrKind::Physical(hwaddr) => unsafe {
                #[cfg(emulation_mode = "usermode")]
                {
                    // For now the default behaviour is to fall back to virtual addresses
                    emu.write_mem(hwaddr.try_into().unwrap(), input_sliced);
                }
                #[cfg(emulation_mode = "systemmode")]
                {
                    emu.write_phys_mem(hwaddr, input_sliced);
                }
            },
            GuestAddrKind::Virtual(vaddr) => unsafe {
                self.cpu
                    .as_ref()
                    .unwrap()
                    .write_mem(vaddr.try_into().unwrap(), input_sliced);
            },
        };

        if let Some(backdoor) = backdoor {
            backdoor
                .ret(
                    &self.cpu.as_ref().unwrap(),
                    input_sliced.len().try_into().unwrap(),
                )
                .unwrap();
        }
    }
}

impl Display for CommandInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:x} max nb bytes)", self.addr, self.max_input_size)
    }
}

// TODO: Rework with generics for command handlers?
pub trait IsEmuExitHandler: Sized + Debug {
    fn try_put_input(&mut self, emu: &Emulator<Self>, input: &BytesInput);

    fn handle(
        &mut self,
        exit_reason: Result<EmuExitReason, EmuExitReasonError>,
        emu: &Emulator<Self>,
        input: &BytesInput,
    ) -> Result<InnerHandlerResult, HandlerError>;
}

pub enum InnerHandlerResult {
    EndOfRun(ExitKind), // The run is over and the emulator is ready for the next iteration.
    ReturnToHarness(EmuExitReason), // Return to the harness immediately. Can happen at any point of the run when the handler is not supposed to handle a request.
    Continue,                       // Resume QEMU and continue to run the handler.
    Interrupt,                      // QEMU has been interrupted by user.
}

#[derive(Clone, Debug)]
pub struct NopEmuExitHandler;

impl IsEmuExitHandler for NopEmuExitHandler {
    fn try_put_input(&mut self, _: &Emulator<Self>, _: &BytesInput) {}

    fn handle(
        &mut self,
        exit_reason: Result<EmuExitReason, EmuExitReasonError>,
        _: &Emulator<Self>,
        _: &BytesInput,
    ) -> Result<InnerHandlerResult, HandlerError> {
        match exit_reason {
            Ok(reason) => Ok(InnerHandlerResult::ReturnToHarness(reason)),
            Err(error) => return Err(error)?,
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

use crate::sync_exit::{SyncExit, SyncExitError};

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

    static mut libafl_dump_core_hook: unsafe extern "C" fn(i32);
    static mut libafl_force_dfl: i32;
}

// TODO rely completely on libafl_qemu_sys
extern "C" {
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
        data: *const (),
    );
    fn libafl_qemu_gdb_reply(buf: *const u8, len: usize);
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FatPtr(pub *const c_void, pub *const c_void);

static mut GDB_COMMANDS: Vec<FatPtr> = vec![];

extern "C" fn gdb_cmd(data: *const (), buf: *const u8, len: usize) -> i32 {
    unsafe {
        let closure = &mut *(data as *mut Box<
            dyn for<'r> FnMut(&Emulator<NopEmuExitHandler>, &'r str) -> bool,
        >);
        let cmd = std::str::from_utf8_unchecked(std::slice::from_raw_parts(buf, len));
        let emu = Emulator::<NopEmuExitHandler>::new_empty();
        i32::from(closure(&emu, cmd))
    }
}

#[derive(Debug, Clone)]
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
    fn read_function_argument<T>(&self, conv: CallingConvention, idx: i32) -> Result<T, String>
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
    pub fn emulator(&self) -> Emulator<NopEmuExitHandler> {
        Emulator::<NopEmuExitHandler>::new_empty()
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

    // TODO expose tlb_set_dirty and tlb_reset_dirty

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

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct HookId(pub(crate) usize);

use std::pin::Pin;

use libafl_bolts::os::unix_signals::Signal;

use crate::breakpoint::Breakpoint;

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
    End(QemuShutdownCause), // QEMU ended for some reason.
    Breakpoint(Breakpoint), // Breakpoint triggered. Contains the address of the trigger.
    SyncBackdoor(SyncExit), // Synchronous backdoor: The guest triggered a backdoor and should return to LibAFL.
}

/// High level result when finishing to handle requests
#[derive(Debug, Clone)]
pub enum HandlerResult {
    UnhandledExit(EmuExitReason), // QEMU exit not handled by the current exit handler.
    EndOfRun(ExitKind),           // QEMU ended the current run and should pass some exit kind.
    Interrupted,                  // User sent an interrupt signal
}

impl From<EmuExitReasonError> for HandlerError {
    fn from(error: EmuExitReasonError) -> Self {
        HandlerError::EmuExitReasonError(error)
    }
}

impl From<SyncExitError> for HandlerError {
    fn from(error: SyncExitError) -> Self {
        HandlerError::SyncExitError(error)
    }
}

impl fmt::Display for EmuExitReason {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            EmuExitReason::End(shutdown_cause) => write!(f, "End: {:?}", shutdown_cause),
            EmuExitReason::Breakpoint(bp) => write!(f, "{}", bp),
            EmuExitReason::SyncBackdoor(sync_backdoor) => {
                write!(f, "Sync backdoor exit: {sync_backdoor}")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum EmuExitReasonError {
    UnknownKind,
    UnexpectedExit,
    SyncBackdoorError(SyncExitError),
    BreakpointNotFound(GuestAddr),
}

impl From<SyncExitError> for EmuExitReasonError {
    fn from(sync_backdoor_error: SyncExitError) -> Self {
        EmuExitReasonError::SyncBackdoorError(sync_backdoor_error)
    }
}

impl<E> TryFrom<&Emulator<E>> for EmuExitReason
where
    E: IsEmuExitHandler,
{
    type Error = EmuExitReasonError;
    fn try_from(emu: &Emulator<E>) -> Result<Self, Self::Error> {
        let exit_reason = unsafe { libafl_get_exit_reason() };
        if exit_reason.is_null() {
            Err(EmuExitReasonError::UnexpectedExit)
        } else {
            let exit_reason: &mut libafl_qemu_sys::libafl_exit_reason =
                unsafe { transmute(&mut *exit_reason) };
            Ok(match exit_reason.kind {
                libafl_qemu_sys::libafl_exit_reason_kind_INTERNAL => unsafe {
                    let qemu_shutdown_cause: QemuShutdownCause =
                        match exit_reason.data.internal.cause {
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_NONE => {
                                QemuShutdownCause::None
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_ERROR => {
                                QemuShutdownCause::HostError
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_QMP_QUIT => {
                                QemuShutdownCause::HostQmpQuit
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_QMP_SYSTEM_RESET => {
                                QemuShutdownCause::HostQmpSystemReset
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_SIGNAL => {
                                QemuShutdownCause::HostSignal(
                                    Signal::try_from(exit_reason.data.internal.signal).unwrap(),
                                )
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_HOST_UI => {
                                QemuShutdownCause::HostUi
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_GUEST_SHUTDOWN => {
                                QemuShutdownCause::GuestShutdown
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_GUEST_RESET => {
                                QemuShutdownCause::GuestReset
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_GUEST_PANIC => {
                                QemuShutdownCause::GuestPanic
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_SUBSYSTEM_RESET => {
                                QemuShutdownCause::SubsystemReset
                            }
                            libafl_qemu_sys::ShutdownCause_SHUTDOWN_CAUSE_SNAPSHOT_LOAD => {
                                QemuShutdownCause::SnapshotLoad
                            }

                            _ => panic!("shutdown cause not handled."),
                        };

                    EmuExitReason::End(qemu_shutdown_cause)
                },
                libafl_qemu_sys::libafl_exit_reason_kind_BREAKPOINT => unsafe {
                    let bp_addr = exit_reason.data.breakpoint.addr;
                    let bp = emu
                        .breakpoints
                        .borrow()
                        .get(&bp_addr)
                        .ok_or(EmuExitReasonError::BreakpointNotFound(bp_addr))?
                        .clone();
                    EmuExitReason::Breakpoint(bp)
                },
                libafl_qemu_sys::libafl_exit_reason_kind_SYNC_BACKDOOR => {
                    EmuExitReason::SyncBackdoor(emu.try_into()?)
                }
                _ => return Err(EmuExitReasonError::UnknownKind),
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
pub struct Emulator<E>
where
    E: IsEmuExitHandler,
{
    exit_handler: RefCell<E>,
    breakpoints: RefCell<HashSet<Breakpoint>>,
    _private: (),
}

#[allow(clippy::unused_self)]
impl<E> Emulator<E>
where
    E: IsEmuExitHandler,
{
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn new(
        args: &[String],
        env: &[(String, String)],
        exit_handler: E,
    ) -> Result<Emulator<E>, EmuError> {
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
                systemmode::qemu_init(
                    argc,
                    argv.as_ptr() as *const *const u8,
                    envp.as_ptr() as *const *const u8,
                );
                libc::atexit(qemu_cleanup_atexit);
                libafl_qemu_sys::syx_snapshot_init(true);
            }
        }
        Ok(Emulator {
            exit_handler: RefCell::new(exit_handler),
            breakpoints: RefCell::new(HashSet::new()),
            _private: (),
        })
    }

    #[must_use]
    pub fn get() -> Option<Emulator<NopEmuExitHandler>> {
        unsafe {
            if EMULATOR_IS_INITIALIZED {
                Some(Emulator::<NopEmuExitHandler>::new_empty())
            } else {
                None
            }
        }
    }

    #[must_use]
    pub(crate) fn new_empty() -> Emulator<NopEmuExitHandler> {
        Emulator {
            exit_handler: RefCell::new(NopEmuExitHandler),
            breakpoints: RefCell::new(HashSet::new()),
            _private: (),
        }
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

    pub fn add_breakpoint(&self, mut bp: Breakpoint, enable: bool) {
        if enable {
            bp.enable(self);
        }

        self.breakpoints.borrow_mut().insert(bp);
    }

    pub fn remove_breakpoint(&self, bp: &mut Breakpoint) {
        bp.disable(self);

        self.breakpoints.borrow_mut().remove(bp);
    }

    pub fn set_breakpoint_addr(&self, addr: GuestAddr) {
        unsafe {
            libafl_qemu_set_breakpoint(addr.into());
        }
    }

    pub fn unset_breakpoint_addr(&self, addr: GuestAddr) {
        unsafe {
            libafl_qemu_remove_breakpoint(addr.into());
        }
    }

    pub fn entry_break(&self, addr: GuestVirtAddr) {
        let mut bp = Breakpoint::without_command(addr as GuestAddr, false);
        self.add_breakpoint(bp.clone(), true);
        unsafe {
            // TODO: decide what to do with sync exit here: ignore or check for bp exit?
            self.run().unwrap();
        }
        self.remove_breakpoint(&mut bp);
    }

    /// This function will run the emulator until the exit handler decides to stop the execution for
    /// whatever reason, depending on the choosen handler.
    /// It is a higher-level abstraction of [`Emulator::run`] that will take care of some part of the runtime logic,
    /// returning only when something interesting happen.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run_handle(&self, input: &BytesInput) -> Result<HandlerResult, HandlerError> {
        loop {
            self.exit_handler.borrow_mut().try_put_input(self, input);
            let exit_reason = self.run();
            let handler_res = self
                .exit_handler
                .borrow_mut()
                .handle(exit_reason, self, input)?;
            match handler_res {
                InnerHandlerResult::ReturnToHarness(exit_reason) => {
                    return Ok(HandlerResult::UnhandledExit(exit_reason))
                }
                InnerHandlerResult::EndOfRun(exit_kind) => {
                    return Ok(HandlerResult::EndOfRun(exit_kind))
                }
                InnerHandlerResult::Interrupt => return Ok(HandlerResult::Interrupted),
                InnerHandlerResult::Continue => {}
            }
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
    ) -> HookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, GuestAddr) = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_qemu_set_hook(
                addr.into(),
                Some(callback),
                data,
                i32::from(invalidate_block),
            );
            HookId(num)
        }
    }

    #[must_use]
    pub fn remove_hook(&self, id: HookId, invalidate_block: bool) -> bool {
        unsafe { libafl_qemu_sys::libafl_qemu_remove_hook(id.0, i32::from(invalidate_block)) != 0 }
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
    ) -> HookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<extern "C" fn(u64, GuestAddr, GuestAddr) -> u64> =
                core::mem::transmute(gen);
            let exec: Option<extern "C" fn(u64, u64)> = core::mem::transmute(exec);
            let num = libafl_qemu_sys::libafl_add_edge_hook(gen, exec, data);
            HookId(num)
        }
    }

    pub fn add_block_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr) -> u64>,
        post_gen: Option<extern "C" fn(T, GuestAddr, GuestUsize)>,
        exec: Option<extern "C" fn(T, u64)>,
    ) -> HookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<extern "C" fn(u64, GuestAddr) -> u64> = core::mem::transmute(gen);
            let post_gen: Option<extern "C" fn(u64, GuestAddr, GuestUsize)> =
                core::mem::transmute(post_gen);
            let exec: Option<extern "C" fn(u64, u64)> = core::mem::transmute(exec);
            let num = libafl_qemu_sys::libafl_add_block_hook(gen, post_gen, exec, data);
            HookId(num)
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
    ) -> HookId {
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
            HookId(num)
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
    ) -> HookId {
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
            HookId(num)
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
    ) -> HookId {
        unsafe {
            let data: u64 = data.into().0;
            let gen: Option<extern "C" fn(u64, GuestAddr, usize) -> u64> =
                core::mem::transmute(gen);
            let exec1: Option<extern "C" fn(u64, u64, u8, u8)> = core::mem::transmute(exec1);
            let exec2: Option<extern "C" fn(u64, u64, u16, u16)> = core::mem::transmute(exec2);
            let exec4: Option<extern "C" fn(u64, u64, u32, u32)> = core::mem::transmute(exec4);
            let exec8: Option<extern "C" fn(u64, u64, u64, u64)> = core::mem::transmute(exec8);
            let num = libafl_qemu_sys::libafl_add_cmp_hook(gen, exec1, exec2, exec4, exec8, data);
            HookId(num)
        }
    }

    pub fn add_backdoor_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, GuestAddr),
    ) -> HookId {
        unsafe {
            let data: u64 = data.into().0;
            let callback: extern "C" fn(u64, GuestAddr) = core::mem::transmute(callback);
            let num = libafl_qemu_sys::libafl_add_backdoor_hook(Some(callback), data);
            HookId(num)
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

impl<E> ArchExtras for Emulator<E>
where
    E: IsEmuExitHandler,
{
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

    fn read_function_argument<T>(&self, conv: CallingConvention, idx: i32) -> Result<T, String>
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
    use std::convert::TryFrom;

    use pyo3::{exceptions::PyValueError, prelude::*, types::PyInt};

    use super::{GuestAddr, GuestUsize, MmapPerms, SyscallHookResult};
    use crate::{IsEmuExitHandler, NopEmuExitHandler};

    static mut PY_SYSCALL_HOOK: Option<PyObject> = None;
    static mut PY_GENERIC_HOOKS: Vec<(GuestAddr, PyObject)> = vec![];

    extern "C" fn py_syscall_hook_wrapper(
        data: u64,
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
        pub emu: super::Emulator<NopEmuExitHandler>,
    }

    #[pymethods]
    impl Emulator<NopEmuExitHandler> {
        #[allow(clippy::needless_pass_by_value)]
        #[new]
        fn new(
            args: Vec<String>,
            env: Vec<(String, String)>,
        ) -> PyResult<Emulator<NopEmuExitHandler>> {
            let emu = super::Emulator::new(&args, &env, NopEmuExitHandler)
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
                let _ = self.emu.run();
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
