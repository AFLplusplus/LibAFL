//! Expose QEMU user `LibAFL` C api to Rust

use core::{
    fmt,
    marker::PhantomData,
    mem::{transmute, MaybeUninit},
    ptr::{addr_of, copy_nonoverlapping, null},
};
use std::{
    cell::{OnceCell, Ref, RefCell, RefMut},
    collections::HashSet,
    ffi::CString,
    fmt::{Debug, Display, Formatter},
    ptr,
};

use libafl::{executors::ExitKind, inputs::BytesInput};
#[cfg(emulation_mode = "systemmode")]
use libafl_qemu_sys::qemu_init;
#[cfg(emulation_mode = "usermode")]
use libafl_qemu_sys::{guest_base, qemu_user_init, VerifyAccess};
use libafl_qemu_sys::{
    libafl_flush_jit, libafl_get_exit_reason, libafl_page_from_addr, libafl_qemu_add_gdb_cmd,
    libafl_qemu_cpu_index, libafl_qemu_current_cpu, libafl_qemu_gdb_reply, libafl_qemu_get_cpu,
    libafl_qemu_num_cpus, libafl_qemu_num_regs, libafl_qemu_read_reg,
    libafl_qemu_remove_breakpoint, libafl_qemu_set_breakpoint, libafl_qemu_trigger_breakpoint,
    libafl_qemu_write_reg, CPUStatePtr, FatPtr, GuestUsize,
};
pub use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};
#[cfg(emulation_mode = "usermode")]
pub use libafl_qemu_sys::{MapInfo, MmapPerms, MmapPermsIter};
use num_traits::Num;
use strum::IntoEnumIterator;

use crate::{command::IsCommand, GuestReg, QemuHelperTuple, Regs, StdInstrumentationFilter};

#[cfg(emulation_mode = "systemmode")]
pub mod systemmode;
#[cfg(emulation_mode = "systemmode")]
pub use systemmode::*;

#[cfg(emulation_mode = "usermode")]
pub mod usermode;
#[cfg(emulation_mode = "usermode")]
pub use usermode::*;

#[derive(Clone)]
pub enum GuestAddrKind {
    Physical(GuestPhysAddr),
    Virtual(GuestVirtAddr),
}

impl Debug for GuestAddrKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestAddrKind::Physical(paddr) => write!(f, "vaddr {paddr:x}"),
            GuestAddrKind::Virtual(vaddr) => write!(f, "paddr {vaddr:x}"),
        }
    }
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

impl Display for GuestAddrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestAddrKind::Physical(phys_addr) => write!(f, "hwaddr 0x{phys_addr:x}"),
            GuestAddrKind::Virtual(virt_addr) => write!(f, "vaddr 0x{virt_addr:x}"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum HandlerError {
    QemuExitReasonError(EmuExitReasonError),
    SMError(SnapshotManagerError),
    SyncBackdoorError(SyncBackdoorError),
    MultipleSnapshotDefinition,
    MultipleInputDefinition,
    SnapshotNotFound,
}

impl From<SnapshotManagerError> for HandlerError {
    fn from(sm_error: SnapshotManagerError) -> Self {
        HandlerError::SMError(sm_error)
    }
}

#[derive(Debug, Clone)]
pub enum SnapshotManagerError {
    SnapshotIdNotFound(SnapshotId),
    MemoryInconsistencies(u64),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SnapshotId {
    id: u64,
}

pub trait IsSnapshotManager: Debug + Clone {
    fn save(&mut self, qemu: &Qemu) -> SnapshotId;
    fn restore(
        &mut self,
        snapshot_id: &SnapshotId,
        qemu: &Qemu,
    ) -> Result<(), SnapshotManagerError>;
}

// TODO: Rework with generics for command handlers?
pub trait EmuExitHandler<QT, S>: Sized + Debug + Clone
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn try_put_input(
        emu: &Emulator<QT, S, Self>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &BytesInput,
    );

    fn handle(
        emu: &Emulator<QT, S, Self>,
        exit_reason: Result<EmuExitReason, EmuExitReasonError>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &BytesInput,
    ) -> Result<InnerHandlerResult, HandlerError>;
}

pub enum InnerHandlerResult {
    EndOfRun(ExitKind), // The run is over and the emulator is ready for the next iteration.
    ReturnToHarness(EmuExitReason), // Return to the harness immediately. Can happen at any point of the run when the handler is not supposed to handle a request.
    Continue,                       // Resume QEMU and continue to run the handler.
    Interrupt,                      // QEMU has been interrupted by user.
}

/// Special kind of Exit handler with no data embedded.
/// As a result, it is safe to transmute from any `Emulator` implementing `EmuExitHandler` to this one,
/// since it won't use any data which could cause type confusion.
#[derive(Clone, Debug)]
pub struct NopEmuExitHandler;

impl<QT, S> EmuExitHandler<QT, S> for NopEmuExitHandler
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn try_put_input(_: &Emulator<QT, S, Self>, _: &mut QemuExecutorState<QT, S>, _: &BytesInput) {}

    fn handle(
        _: &Emulator<QT, S, Self>,
        exit_reason: Result<EmuExitReason, EmuExitReasonError>,
        _: &mut QemuExecutorState<QT, S>,
        _: &BytesInput,
    ) -> Result<InnerHandlerResult, HandlerError> {
        match exit_reason {
            Ok(reason) => Ok(InnerHandlerResult::ReturnToHarness(reason)),
            Err(error) => Err(error)?,
        }
    }
}

/// Synchronous Exit handler maintaining only one snapshot.
#[derive(Debug, Clone)]
pub struct StdEmuExitHandler<SM>
where
    SM: IsSnapshotManager + Clone,
{
    snapshot_manager: RefCell<SM>,
    snapshot_id: OnceCell<SnapshotId>,
    input_location: OnceCell<(EmulatorMemoryChunk, Option<Regs>)>,
}

impl<SM> StdEmuExitHandler<SM>
where
    SM: IsSnapshotManager,
{
    pub fn new(snapshot_manager: SM) -> Self {
        Self {
            snapshot_manager: RefCell::new(snapshot_manager),
            snapshot_id: OnceCell::new(),
            input_location: OnceCell::new(),
        }
    }

    pub fn set_input_location(
        &self,
        input_location: EmulatorMemoryChunk,
        ret_reg: Option<Regs>,
    ) -> Result<(), (EmulatorMemoryChunk, Option<Regs>)> {
        self.input_location.set((input_location, ret_reg))
    }

    pub fn set_snapshot_id(&self, snapshot_id: SnapshotId) -> Result<(), SnapshotId> {
        self.snapshot_id.set(snapshot_id)
    }

    pub fn snapshot_id(&self) -> Option<SnapshotId> {
        Some(*self.snapshot_id.get()?)
    }

    pub fn snapshot_manager_borrow(&self) -> Ref<SM> {
        self.snapshot_manager.borrow()
    }

    pub fn snapshot_manager_borrow_mut(&self) -> RefMut<SM> {
        self.snapshot_manager.borrow_mut()
    }
}

// TODO: replace handlers with generics to permit compile-time customization of handlers
impl<SM, QT, S> EmuExitHandler<QT, S> for StdEmuExitHandler<SM>
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
{
    fn try_put_input(
        emu: &Emulator<QT, S, Self>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &BytesInput,
    ) {
        let exit_handler = emu.state().exit_handler.borrow();

        if let Some((input_location, ret_register)) = exit_handler.input_location.get() {
            let input_command = InputCommand::new(input_location.clone());
            input_command
                .run(emu, qemu_executor_state, input, *ret_register)
                .unwrap();
        }
    }

    fn handle(
        emu: &Emulator<QT, S, Self>,
        exit_reason: Result<EmuExitReason, EmuExitReasonError>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &BytesInput,
    ) -> Result<InnerHandlerResult, HandlerError> {
        let exit_handler = emu.exit_handler().borrow_mut();
        let qemu = emu.qemu();

        let mut exit_reason = match exit_reason {
            Ok(exit_reason) => exit_reason,
            Err(exit_error) => match exit_error {
                EmuExitReasonError::UnexpectedExit => {
                    if let Some(snapshot_id) = exit_handler.snapshot_id.get() {
                        exit_handler
                            .snapshot_manager
                            .borrow_mut()
                            .restore(snapshot_id, qemu)?;
                    }
                    return Ok(InnerHandlerResult::EndOfRun(ExitKind::Crash));
                }
                _ => Err(exit_error)?,
            },
        };

        let (command, ret_reg): (Option<Command>, Option<Regs>) = match &mut exit_reason {
            EmuExitReason::End(shutdown_cause) => match shutdown_cause {
                QemuShutdownCause::HostSignal(Signal::SigInterrupt) => {
                    return Ok(InnerHandlerResult::Interrupt)
                }
                QemuShutdownCause::GuestPanic => {
                    return Ok(InnerHandlerResult::EndOfRun(ExitKind::Crash))
                }
                _ => panic!("Unhandled QEMU shutdown cause: {shutdown_cause:?}."),
            },
            EmuExitReason::Breakpoint(bp) => (bp.trigger(qemu).cloned(), None),
            EmuExitReason::SyncBackdoor(sync_backdoor) => {
                let command = sync_backdoor.command().clone();
                (Some(command), Some(sync_backdoor.ret_reg()))
            }
        };

        // manually drop ref cell here to avoid keeping it alive in cmd.
        drop(exit_handler);

        if let Some(cmd) = command {
            cmd.run(emu, qemu_executor_state, input, ret_reg)
        } else {
            Ok(InnerHandlerResult::ReturnToHarness(exit_reason))
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

#[allow(clippy::vec_box)]
static mut GDB_COMMANDS: Vec<Box<FatPtr>> = vec![];

extern "C" fn gdb_cmd(data: *const (), buf: *const u8, len: usize) -> i32 {
    unsafe {
        let closure = &mut *(data as *mut Box<dyn for<'r> FnMut(&Qemu, &'r str) -> bool>);
        let cmd = std::str::from_utf8_unchecked(std::slice::from_raw_parts(buf, len));
        let qemu = Qemu::get_unchecked();
        i32::from(closure(&qemu, cmd))
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
    pub fn qemu(&self) -> Qemu {
        unsafe { Qemu::get_unchecked() }
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

use std::{pin::Pin, ptr::NonNull};

use libafl::state::{HasExecutions, State};
use libafl_bolts::os::unix_signals::Signal;

use crate::{
    breakpoint::Breakpoint,
    command::{Command, EmulatorMemoryChunk, InputCommand},
    executor::QemuExecutorState,
};

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
    End(QemuShutdownCause),     // QEMU ended for some reason.
    Breakpoint(Breakpoint),     // Breakpoint triggered. Contains the address of the trigger.
    SyncBackdoor(SyncBackdoor), // Synchronous backdoor: The guest triggered a backdoor and should return to LibAFL.
}

#[derive(Debug, Clone)]
pub enum QemuExitReason {
    End(QemuShutdownCause), // QEMU ended for some reason.
    Breakpoint(GuestAddr),  // Breakpoint triggered. Contains the address of the trigger.
    SyncBackdoor, // Synchronous backdoor: The guest triggered a backdoor and should return to LibAFL.
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
        HandlerError::QemuExitReasonError(error)
    }
}

impl From<SyncBackdoorError> for HandlerError {
    fn from(error: SyncBackdoorError) -> Self {
        HandlerError::SyncBackdoorError(error)
    }
}

impl Display for QemuExitReason {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            QemuExitReason::End(shutdown_cause) => write!(f, "End: {shutdown_cause:?}"),
            QemuExitReason::Breakpoint(bp) => write!(f, "Breakpoint: {bp}"),
            QemuExitReason::SyncBackdoor => write!(f, "Sync Backdoor"), // QemuExitReason::SyncBackdoor(sync_backdoor) => {
                                                                        //     write!(f, "Sync backdoor exit: {sync_backdoor}")
                                                                        // }
        }
    }
}

impl Display for EmuExitReason {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            EmuExitReason::End(shutdown_cause) => write!(f, "End: {shutdown_cause:?}"),
            EmuExitReason::Breakpoint(bp) => write!(f, "{bp}"),
            EmuExitReason::SyncBackdoor(sync_backdoor) => {
                write!(f, "Sync backdoor exit: {sync_backdoor}")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum QemuExitReasonError {
    UnknownKind, // Exit reason was not NULL, but exit kind is unknown. Should never happen.
    UnexpectedExit, // Qemu exited without going through an expected exit point. Can be caused by a crash for example.
}

#[derive(Debug, Clone)]
pub enum EmuExitReasonError {
    UnknownKind,
    UnexpectedExit,
    SyncBackdoorError(SyncBackdoorError),
    BreakpointNotFound(GuestAddr),
}

impl From<SyncBackdoorError> for EmuExitReasonError {
    fn from(sync_backdoor_error: SyncBackdoorError) -> Self {
        EmuExitReasonError::SyncBackdoorError(sync_backdoor_error)
    }
}

impl std::error::Error for EmuError {}

impl Display for EmuError {
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

static mut EMULATOR_STATE: *mut () = ptr::null_mut();
static mut QEMU_IS_INITIALIZED: bool = false;

/// The thin wrapper around QEMU.
/// It is considered unsafe to use it directly.
/// Prefer using `Emulator` instead in case of doubt.
#[derive(Clone, Copy, Debug)]
pub struct Qemu {
    _private: (),
}

pub struct EmulatorState<QT, S, E>
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
    E: EmuExitHandler<QT, S>,
{
    exit_handler: RefCell<E>,
    breakpoints: RefCell<HashSet<Breakpoint>>,
    _phantom: PhantomData<(QT, S)>,
}

#[derive(Clone, Debug)]
pub struct Emulator<QT, S, E>
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
    E: EmuExitHandler<QT, S>,
{
    state: ptr::NonNull<EmulatorState<QT, S, E>>,
    qemu: Qemu,
}

#[allow(clippy::unused_self)]
impl Qemu {
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn init(args: &[String], env: &[(String, String)]) -> Result<Self, EmuError> {
        if args.is_empty() {
            return Err(EmuError::EmptyArgs);
        }

        let argc = args.len();
        if i32::try_from(argc).is_err() {
            return Err(EmuError::TooManyArgs(argc));
        }

        unsafe {
            if QEMU_IS_INITIALIZED {
                return Err(EmuError::MultipleInstances);
            }
            QEMU_IS_INITIALIZED = true;
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

        Ok(Qemu { _private: () })
    }

    /// Get a QEMU object.
    /// Same as `Qemu::get`, but without checking whether QEMU has been correctly initialized.
    ///
    /// # Safety
    ///
    /// Should not be used if `Qemu::init` has never been used before (otherwise QEMU will not be initialized, and a crash will occur).
    /// Prefer `Qemu::get` for a safe version of this method.
    #[must_use]
    pub unsafe fn get_unchecked() -> Self {
        Qemu { _private: () }
    }

    #[must_use]
    pub fn get() -> Option<Self> {
        unsafe {
            if QEMU_IS_INITIALIZED {
                Some(Qemu { _private: () })
            } else {
                None
            }
        }
    }

    fn post_run(&self) -> Result<QemuExitReason, QemuExitReasonError> {
        let exit_reason = unsafe { libafl_get_exit_reason() };
        if exit_reason.is_null() {
            Err(QemuExitReasonError::UnexpectedExit)
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

                    QemuExitReason::End(qemu_shutdown_cause)
                },
                libafl_qemu_sys::libafl_exit_reason_kind_BREAKPOINT => unsafe {
                    let bp_addr = exit_reason.data.breakpoint.addr;
                    QemuExitReason::Breakpoint(bp_addr)
                },
                libafl_qemu_sys::libafl_exit_reason_kind_SYNC_BACKDOOR => {
                    QemuExitReason::SyncBackdoor
                }
                _ => return Err(QemuExitReasonError::UnknownKind),
            })
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
    pub fn page_from_addr(&self, addr: GuestAddr) -> GuestAddr {
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
            match self.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                _ => panic!("Unexpected QEMU exit."),
            }
        }
        self.remove_breakpoint(addr);
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
}

impl ArchExtras for Qemu {
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

#[allow(clippy::unused_self)]
impl<QT, S, E> Emulator<QT, S, E>
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
    E: EmuExitHandler<QT, S>,
{
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn new(
        args: &[String],
        env: &[(String, String)],
        exit_handler: E,
    ) -> Result<Self, EmuError> {
        let qemu = Qemu::init(args, env)?;

        Self::new_with_qemu(qemu, exit_handler)
    }

    pub fn new_with_qemu(qemu: Qemu, exit_handler: E) -> Result<Self, EmuError> {
        let emu_state = Box::new(EmulatorState {
            exit_handler: RefCell::new(exit_handler),
            breakpoints: RefCell::new(HashSet::new()),
            _phantom: PhantomData,
        });

        let emu_state_ptr = unsafe {
            let emu_ptr = NonNull::from(Box::leak(emu_state));
            EMULATOR_STATE = emu_ptr.as_ptr() as *mut ();
            emu_ptr
        };

        Ok(Emulator {
            state: emu_state_ptr,
            qemu,
        })
    }

    #[must_use]
    pub fn qemu(&self) -> &Qemu {
        &self.qemu
    }

    #[must_use]
    pub fn state(&self) -> &EmulatorState<QT, S, E> {
        unsafe { self.state.as_ref() }
    }

    #[must_use]
    pub fn state_mut(&mut self) -> &mut EmulatorState<QT, S, E> {
        unsafe { self.state.as_mut() }
    }

    #[must_use]
    pub fn exit_handler(&self) -> &RefCell<E> {
        &self.state().exit_handler
    }

    #[must_use]
    pub fn get() -> Option<Emulator<QT, S, NopEmuExitHandler>> {
        unsafe {
            if QEMU_IS_INITIALIZED {
                Some(Emulator::<QT, S, NopEmuExitHandler>::get_unchecked())
            } else {
                None
            }
        }
    }

    /// Get an empty emulator.
    /// Same as `Emulator::get`, but without checking whether QEMU has been correctly initialized.
    ///
    /// # Safety
    ///
    /// Should not be used if `Qemu::init` or `Emulator::new` has never been used before (otherwise QEMU will not be initialized, and a crash will occur).
    /// Prefer `Emulator::get` for a safe version of this method.
    #[must_use]
    pub unsafe fn get_unchecked() -> Emulator<QT, S, NopEmuExitHandler> {
        Emulator {
            state: NonNull::dangling(),
            qemu: Qemu::get_unchecked(),
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::cast_sign_loss)]
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn num_cpus(&self) -> usize {
        self.qemu.num_cpus()
    }

    #[must_use]
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn current_cpu(&self) -> Option<CPU> {
        self.qemu.current_cpu()
    }

    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn cpu_from_index(&self, index: usize) -> CPU {
        self.qemu.cpu_from_index(index)
    }

    #[must_use]
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn page_from_addr(&self, addr: GuestAddr) -> GuestAddr {
        self.qemu.page_from_addr(addr)
    }

    //#[must_use]
    /*pub fn page_size() -> GuestUsize {
        unsafe { libafl_page_size }
    }*/

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub unsafe fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
        self.qemu.write_mem(addr, buf);
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub unsafe fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) {
        self.qemu.read_mem(addr, buf);
    }

    #[must_use]
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn num_regs(&self) -> i32 {
        self.qemu.num_regs()
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), String>
    where
        T: Num + PartialOrd + Copy + Into<GuestReg>,
        R: Into<i32>,
    {
        self.qemu.write_reg(reg, val)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn read_reg<R, T>(&self, reg: R) -> Result<T, String>
    where
        T: Num + PartialOrd + Copy + From<GuestReg>,
        R: Into<i32>,
    {
        self.qemu.read_reg(reg)
    }

    pub fn add_breakpoint(&self, mut bp: Breakpoint, enable: bool) {
        if enable {
            bp.enable(&self.qemu);
        }

        self.state().breakpoints.borrow_mut().insert(bp);
    }

    pub fn remove_breakpoint(&self, bp: &mut Breakpoint) {
        bp.disable(&self.qemu);

        self.state().breakpoints.borrow_mut().remove(bp);
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn entry_break(&self, addr: GuestAddr) {
        self.qemu.entry_break(addr);
    }

    /// This function will run the emulator until the next breakpoint, or until finish.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    unsafe fn run_qemu(&self) -> Result<EmuExitReason, EmuExitReasonError> {
        match self.qemu.run() {
            Ok(qemu_exit_reason) => Ok(match qemu_exit_reason {
                QemuExitReason::End(qemu_shutdown_cause) => EmuExitReason::End(qemu_shutdown_cause),
                QemuExitReason::Breakpoint(bp_addr) => {
                    let bp = self
                        .state()
                        .breakpoints
                        .borrow()
                        .get(&bp_addr)
                        .ok_or(EmuExitReasonError::BreakpointNotFound(bp_addr))?
                        .clone();
                    EmuExitReason::Breakpoint(bp)
                }
                QemuExitReason::SyncBackdoor => EmuExitReason::SyncBackdoor(self.try_into()?),
            }),
            Err(qemu_exit_reason_error) => Err(match qemu_exit_reason_error {
                QemuExitReasonError::UnexpectedExit => EmuExitReasonError::UnexpectedExit,
                QemuExitReasonError::UnknownKind => EmuExitReasonError::UnknownKind,
            }),
        }
    }

    /// This function will run the emulator until the exit handler decides to stop the execution for
    /// whatever reason, depending on the choosen handler.
    /// It is a higher-level abstraction of [`Emulator::run`] that will take care of some part of the runtime logic,
    /// returning only when something interesting happen.
    ///
    /// # Safety
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run(
        &self,
        input: &BytesInput,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
    ) -> Result<HandlerResult, HandlerError> {
        loop {
            // Insert input if the location is already known
            E::try_put_input(self, qemu_executor_state, input);

            // Run QEMU
            let exit_reason = self.run_qemu();

            // Handle QEMU exit
            let handler_res = E::handle(self, exit_reason, qemu_executor_state, input)?;

            // Return to harness
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

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn flush_jit(&self) {
        self.qemu.flush_jit();
    }

    // TODO set T lifetime to be like Emulator
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn set_hook<T: Into<HookData>>(
        &self,
        data: T,
        addr: GuestAddr,
        callback: extern "C" fn(T, GuestAddr),
        invalidate_block: bool,
    ) -> InstructionHookId {
        self.qemu.set_hook(data, addr, callback, invalidate_block)
    }

    #[must_use]
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn remove_hook(&self, id: impl HookId, invalidate_block: bool) -> bool {
        self.qemu.remove_hook(id, invalidate_block)
    }

    #[must_use]
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn remove_hooks_at(&self, addr: GuestAddr, invalidate_block: bool) -> usize {
        self.qemu.remove_hooks_at(addr, invalidate_block)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn add_edge_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr, GuestAddr) -> u64>,
        exec: Option<extern "C" fn(T, u64)>,
    ) -> EdgeHookId {
        self.qemu.add_edge_hooks(data, gen, exec)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn add_block_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr) -> u64>,
        post_gen: Option<extern "C" fn(T, GuestAddr, GuestUsize)>,
        exec: Option<extern "C" fn(T, u64)>,
    ) -> BlockHookId {
        self.qemu.add_block_hooks(data, gen, post_gen, exec)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
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
        self.qemu
            .add_read_hooks(data, gen, exec1, exec2, exec4, exec8, exec_n)
    }

    // TODO add MemOp info
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
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
        self.qemu
            .add_write_hooks(data, gen, exec1, exec2, exec4, exec8, exec_n)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn add_cmp_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<extern "C" fn(T, GuestAddr, usize) -> u64>,
        exec1: Option<extern "C" fn(T, u64, u8, u8)>,
        exec2: Option<extern "C" fn(T, u64, u16, u16)>,
        exec4: Option<extern "C" fn(T, u64, u32, u32)>,
        exec8: Option<extern "C" fn(T, u64, u64, u64)>,
    ) -> CmpHookId {
        self.qemu
            .add_cmp_hooks(data, gen, exec1, exec2, exec4, exec8)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn add_backdoor_hook<T: Into<HookData>>(
        &self,
        data: T,
        callback: extern "C" fn(T, GuestAddr),
    ) -> BackdoorHookId {
        self.qemu.add_backdoor_hook(data, callback)
    }

    #[allow(clippy::type_complexity)]
    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn add_gdb_cmd(&self, callback: Box<dyn FnMut(&Qemu, &str) -> bool>) {
        self.qemu.add_gdb_cmd(callback);
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn gdb_reply(&self, output: &str) {
        self.qemu.gdb_reply(output);
    }
}

// impl<QT, S, E> ArchExtras for Emulator<QT, S, E>
// where
//     QT: QemuHelperTuple<S>,
//     S: State + HasExecutions,
//     E: EmuExitHandler<QT, S>,
// {
//     fn read_return_address<T>(&self) -> Result<T, String>
//     where
//         T: From<GuestReg>,
//     {
//         self.qemu.read_return_address()
//     }
//
//     fn write_return_address<T>(&self, val: T) -> Result<(), String>
//     where
//         T: Into<GuestReg>,
//     {
//         self.qemu.write_return_address(val)
//     }
//
//     fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, String>
//     where
//         T: From<GuestReg>,
//     {
//         self.qemu.read_function_argument(conv, idx)
//     }
//
//     fn write_function_argument<T>(
//         &self,
//         conv: CallingConvention,
//         idx: i32,
//         val: T,
//     ) -> Result<(), String>
//     where
//         T: Into<GuestReg>,
//     {
//         self.qemu.write_function_argument(conv, idx, val)
//     }
// }

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
    pub struct Qemu {
        pub qemu: super::Qemu,
    }

    #[pymethods]
    impl Qemu {
        #[allow(clippy::needless_pass_by_value)]
        #[new]
        fn new(args: Vec<String>, env: Vec<(String, String)>) -> PyResult<Qemu> {
            let qemu = super::Qemu::init(&args, &env)
                .map_err(|e| PyValueError::new_err(format!("{e}")))?;

            Ok(Qemu { qemu })
        }

        fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
            unsafe {
                self.qemu.write_mem(addr, buf);
            }
        }

        fn read_mem(&self, addr: GuestAddr, size: usize) -> Vec<u8> {
            let mut buf = vec![0; size];
            unsafe {
                self.qemu.read_mem(addr, &mut buf);
            }
            buf
        }

        fn num_regs(&self) -> i32 {
            self.qemu.num_regs()
        }

        fn write_reg(&self, reg: i32, val: GuestUsize) -> PyResult<()> {
            self.qemu.write_reg(reg, val).map_err(PyValueError::new_err)
        }

        fn read_reg(&self, reg: i32) -> PyResult<GuestUsize> {
            self.qemu.read_reg(reg).map_err(PyValueError::new_err)
        }

        fn set_breakpoint(&self, addr: GuestAddr) {
            self.qemu.set_breakpoint(addr);
        }

        fn entry_break(&self, addr: GuestAddr) {
            self.qemu.entry_break(addr);
        }

        fn remove_breakpoint(&self, addr: GuestAddr) {
            self.qemu.remove_breakpoint(addr);
        }

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

        fn flush_jit(&self) {
            self.qemu.flush_jit();
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
                PY_SYSCALL_HOOK = Some(hook);
            }
            self.qemu
                .add_pre_syscall_hook(0u64, py_syscall_hook_wrapper);
        }

        fn set_hook(&self, addr: GuestAddr, hook: PyObject) {
            unsafe {
                let idx = PY_GENERIC_HOOKS.len();
                PY_GENERIC_HOOKS.push((addr, hook));
                self.qemu
                    .set_hook(idx as u64, addr, py_generic_hook_wrapper, true);
            }
        }

        fn remove_hooks_at(&self, addr: GuestAddr) -> usize {
            unsafe {
                PY_GENERIC_HOOKS.retain(|(a, _)| *a != addr);
            }
            self.qemu.remove_hooks_at(addr, true)
        }
    }
}
