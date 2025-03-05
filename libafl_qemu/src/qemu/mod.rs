//! Low-level QEMU library
//!
//! This module exposes the low-level QEMU library through [`Qemu`].
//! To access higher-level features of QEMU, it is recommended to use [`crate::Emulator`] instead.

use core::{
    cmp::{Ordering, PartialOrd},
    fmt, ptr, slice,
};
use std::{
    ffi::{CString, c_void},
    fmt::{Display, Formatter, Write},
    mem::{MaybeUninit, transmute},
    ops::{Deref, Range},
    pin::Pin,
    ptr::copy_nonoverlapping,
    sync::OnceLock,
};

#[cfg(feature = "systemmode")]
use libafl_bolts::Error;
use libafl_bolts::os::unix_signals::Signal;
use libafl_qemu_sys::{
    CPUArchState, CPUStatePtr, FatPtr, GuestAddr, GuestPhysAddr, GuestUsize, GuestVirtAddr,
    libafl_flush_jit, libafl_get_exit_reason, libafl_page_from_addr, libafl_qemu_add_gdb_cmd,
    libafl_qemu_cpu_index, libafl_qemu_current_cpu, libafl_qemu_gdb_reply, libafl_qemu_get_cpu,
    libafl_qemu_init, libafl_qemu_num_cpus, libafl_qemu_num_regs, libafl_qemu_read_reg,
    libafl_qemu_remove_breakpoint, libafl_qemu_set_breakpoint, libafl_qemu_trigger_breakpoint,
    libafl_qemu_write_reg,
};
#[cfg(feature = "systemmode")]
use libafl_qemu_sys::{libafl_qemu_remove_hw_breakpoint, libafl_qemu_set_hw_breakpoint};
use num_traits::Num;
use strum::IntoEnumIterator;

use crate::{GuestAddrKind, GuestReg, Regs};

pub mod config;
use config::QemuConfig;

pub mod error;
pub use error::{
    QemuError, QemuExitError, QemuInitError, QemuRWError, QemuRWErrorCause, QemuRWErrorKind,
};

#[cfg(feature = "usermode")]
mod usermode;
#[cfg(feature = "usermode")]
pub use usermode::*;

#[cfg(feature = "systemmode")]
mod systemmode;
#[cfg(feature = "systemmode")]
pub use systemmode::*;

mod hooks;
pub use hooks::*;
use libafl_bolts::{AsSliceMut, vec_init};

static mut QEMU_IS_INITIALIZED: bool = false;
static mut QEMU_IS_RUNNING: bool = false;

pub(super) static QEMU_CONFIG: OnceLock<QemuConfig> = OnceLock::new();

#[expect(clippy::vec_box)]
static mut GDB_COMMANDS: Vec<Box<FatPtr>> = Vec::new();

pub trait HookId {
    fn remove(&self, invalidate_block: bool) -> bool;
}

pub trait ArchExtras {
    fn read_return_address(&self) -> Result<GuestReg, QemuRWError>;
    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>;
    fn read_function_argument_with_cc(
        &self,
        idx: u8,
        conv: CallingConvention,
    ) -> Result<GuestReg, QemuRWError>;

    fn write_function_argument_with_cc<T>(
        &self,
        idx: u8,
        val: T,
        conv: CallingConvention,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>;
}

#[derive(Debug, Clone)]
pub enum QemuExitReason {
    /// QEMU ended for some internal reason
    End(QemuShutdownCause),

    /// Breakpoint triggered. Contains the address of the trigger
    Breakpoint(GuestAddr),

    /// Synchronous exit: The guest triggered a backdoor and should return to `LibAFL`.
    SyncExit,

    /// Timeout, and it has been requested to be handled by the harness.
    Timeout,
}

/// The thin wrapper around QEMU.
/// It is considered unsafe to use it directly.
/// Prefer using `Emulator` instead in case of doubt.
#[derive(Clone, Copy, Debug)]
pub struct Qemu {
    _private: (),
}

#[derive(Clone, Debug)]
pub enum QemuParams {
    // QemuConfig is quite big, at least 240 bytes so we use a Box
    Config(Box<QemuConfig>),
    Cli(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct QemuMemoryChunk {
    addr: GuestAddrKind,
    size: GuestReg,
    cpu: Option<CPU>,
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

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct MemAccessInfo {
    oi: libafl_qemu_sys::MemOpIdx,
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct CPU {
    ptr: CPUStatePtr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CallingConvention {
    SystemV,
    Cdecl,
    Aapcs64,
    Aapcs,
    Hexagon,
    MipsO32,
    Ppc32,
    RiscVilp32,
}

#[derive(Debug)]
pub struct HookData(u64);

unsafe extern "C" fn gdb_cmd(data: *mut c_void, buf: *mut u8, len: usize) -> bool {
    unsafe {
        let closure = &mut *(data as *mut Box<dyn for<'r> FnMut(Qemu, &'r str) -> bool>);
        let cmd = std::str::from_utf8_unchecked(std::slice::from_raw_parts(buf, len));
        let qemu = Qemu::get_unchecked();
        closure(qemu, cmd)
    }
}

impl Display for QemuExitReason {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            QemuExitReason::End(shutdown_cause) => write!(f, "End: {shutdown_cause:?}"),
            QemuExitReason::Breakpoint(bp) => write!(f, "Breakpoint: {bp}"),
            QemuExitReason::SyncExit => write!(f, "Sync Exit"),
            QemuExitReason::Timeout => write!(f, "Timeout"),
        }
    }
}

impl From<QemuConfig> for QemuParams {
    fn from(config: QemuConfig) -> Self {
        QemuParams::Config(Box::new(config))
    }
}

// impl TryFrom<QemuConfigBuilder> for QemuParams {
//     type Error = QemuInitError;
//
//     fn try_from(config_builder: QemuConfigBuilder) -> Result<Self, Self::Error> {
//         Ok(QemuParams::Config(
//             config_builder
//                 .build()
//                 .map_err(QemuInitError::ConfigurationError)?,
//         ))
//     }
// }

impl<T> From<&[T]> for QemuParams
where
    T: AsRef<str>,
{
    fn from(cli: &[T]) -> Self {
        QemuParams::Cli(cli.iter().map(|x| x.as_ref().into()).collect())
    }
}

impl<T> From<&Vec<T>> for QemuParams
where
    T: AsRef<str>,
{
    fn from(cli: &Vec<T>) -> Self {
        cli.as_slice().into()
    }
}

impl<T> From<Vec<T>> for QemuParams
where
    T: AsRef<str>,
{
    fn from(cli: Vec<T>) -> Self {
        (&cli).into()
    }
}

impl QemuParams {
    pub fn to_cli(&self) -> Vec<String> {
        match self {
            QemuParams::Config(cfg) => cfg
                .to_string()
                .split(' ')
                .map(ToString::to_string)
                .collect(),
            QemuParams::Cli(cli) => cli.clone(),
        }
    }
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

impl CPU {
    #[must_use]
    #[expect(clippy::cast_sign_loss)]
    pub fn index(&self) -> usize {
        unsafe { libafl_qemu_cpu_index(self.ptr) as usize }
    }

    pub fn trigger_breakpoint(&self) {
        unsafe {
            libafl_qemu_trigger_breakpoint(self.ptr);
        }
    }

    // TODO expose tlb_set_dirty and tlb_reset_dirty

    #[must_use]
    pub fn num_regs(&self) -> i32 {
        unsafe { libafl_qemu_num_regs(self.ptr) }
    }

    pub fn read_reg<R>(&self, reg: R) -> Result<GuestReg, QemuRWError>
    where
        R: Into<i32> + Clone,
    {
        unsafe {
            let reg_id = reg.clone().into();
            let mut val = MaybeUninit::uninit();
            let success = libafl_qemu_read_reg(self.ptr, reg_id, val.as_mut_ptr() as *mut u8);
            if success == 0 {
                Err(QemuRWError::wrong_reg(
                    QemuRWErrorKind::Write,
                    reg,
                    Some(self.ptr),
                ))
            } else {
                #[cfg(feature = "be")]
                return Ok(GuestReg::from_be(val.assume_init()).into());

                #[cfg(not(feature = "be"))]
                return Ok(GuestReg::from_le(val.assume_init()).into());
            }
        }
    }

    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), QemuRWError>
    where
        R: Into<i32> + Clone,
        T: Into<GuestReg>,
    {
        let reg_id = reg.clone().into();
        #[cfg(feature = "be")]
        let val = GuestReg::to_be(val.into());

        #[cfg(not(feature = "be"))]
        let val = GuestReg::to_le(val.into());

        let success = unsafe { libafl_qemu_write_reg(self.ptr, reg_id, &raw const val as *mut u8) };
        if success == 0 {
            Err(QemuRWError::wrong_reg(
                QemuRWErrorKind::Write,
                reg,
                Some(self.ptr),
            ))
        } else {
            Ok(())
        }
    }

    /// Read a value from a guest address, taking into account the potential MMU / MPU.
    pub fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), QemuRWError> {
        // TODO use gdbstub's target_cpu_memory_rw_debug
        let ret = unsafe {
            libafl_qemu_sys::cpu_memory_rw_debug(
                self.ptr,
                addr as GuestVirtAddr,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                false,
            )
        };

        if ret != 0 {
            Err(QemuRWError::wrong_mem_location(
                QemuRWErrorKind::Read,
                self.ptr,
                addr,
                buf.len(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn read_mem_vec(&self, addr: GuestAddr, len: usize) -> Result<Vec<u8>, QemuRWError> {
        // # Safety
        // This is safe because we read exactly `len` bytes from QEMU.
        unsafe {
            vec_init(len, |buf| {
                self.read_mem(addr, buf.as_slice_mut())?;

                Ok::<(), QemuRWError>(())
            })
        }
    }

    /// Write a value to a guest address, taking into account the potential MMU / MPU.
    pub fn write_mem(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), QemuRWError> {
        // TODO use gdbstub's target_cpu_memory_rw_debug
        let ret = unsafe {
            libafl_qemu_sys::cpu_memory_rw_debug(
                self.ptr,
                addr as GuestVirtAddr,
                buf.as_ptr() as *mut _,
                buf.len(),
                true,
            )
        };

        if ret != 0 {
            Err(QemuRWError::wrong_mem_location(
                QemuRWErrorKind::Write,
                self.ptr,
                addr,
                buf.len(),
            ))
        } else {
            Ok(())
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
            let _ = write!(&mut display, "{sr:>maxl$}: {v:#016x} ");
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

impl<T> From<Pin<&mut T>> for HookData {
    fn from(value: Pin<&mut T>) -> Self {
        unsafe { HookData(transmute::<Pin<&mut T>, u64>(value)) }
    }
}

impl<T> From<Pin<&T>> for HookData {
    fn from(value: Pin<&T>) -> Self {
        unsafe { HookData(transmute::<Pin<&T>, u64>(value)) }
    }
}

impl<T> From<&'static mut T> for HookData {
    fn from(value: &'static mut T) -> Self {
        unsafe { HookData(transmute::<&mut T, u64>(value)) }
    }
}

impl<T> From<&'static T> for HookData {
    fn from(value: &'static T) -> Self {
        unsafe { HookData(transmute::<&T, u64>(value)) }
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

impl Qemu {
    #[expect(clippy::similar_names)]
    pub fn init<T>(params: T) -> Result<Self, QemuInitError>
    where
        T: Into<QemuParams>,
    {
        let params: QemuParams = params.into();

        match &params {
            QemuParams::Config(cfg) => {
                QEMU_CONFIG
                    .set(cfg.deref().clone())
                    .map_err(|_| unreachable!("QEMU_CONFIG was already set but Qemu was not init!"))
                    .expect("Could not set QEMU Config.");
            }
            QemuParams::Cli(_) => {}
        }

        let args = params.to_cli();

        if args.is_empty() {
            return Err(QemuInitError::EmptyArgs);
        }

        let argc = args.len();
        if i32::try_from(argc).is_err() {
            return Err(QemuInitError::TooManyArgs(argc));
        }

        unsafe {
            if QEMU_IS_INITIALIZED {
                return Err(QemuInitError::MultipleInstances);
            }

            QEMU_IS_INITIALIZED = true;
        }

        #[expect(clippy::cast_possible_wrap)]
        let argc = argc as i32;

        let args: Vec<CString> = args
            .iter()
            .map(|x| CString::new(AsRef::<str>::as_ref(x)).unwrap())
            .collect();
        let mut argv: Vec<*const u8> = args.iter().map(|x| x.as_ptr() as *const u8).collect();
        argv.push(ptr::null()); // argv is always null terminated.

        unsafe {
            libafl_qemu_init(argc, argv.as_ptr() as *mut *mut ::std::os::raw::c_char);
        }

        #[cfg(feature = "systemmode")]
        unsafe {
            libafl_qemu_sys::syx_snapshot_init(true);
            libc::atexit(qemu_cleanup_atexit);
        }

        Ok(Qemu { _private: () })
    }

    #[must_use]
    pub fn hooks(&self) -> QemuHooks {
        unsafe { QemuHooks::get_unchecked() }
    }

    /// Get a QEMU object.
    /// Same as `Qemu::get`, but without checking whether QEMU has been correctly initialized.
    /// Since Qemu is a ZST, this operation is free.
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

    /// Get QEMU configuration.
    /// Returns `Some` only if QEMU was initialized with the builder.
    /// Returns `None` if QEMU was initialized with `init` and raw string args.
    #[must_use]
    pub fn get_config(&self) -> Option<&'static QemuConfig> {
        QEMU_CONFIG.get()
    }

    /// This function will run the emulator until the next breakpoint / sync exit, or until finish.
    /// It is a low-level function and simply kicks QEMU.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run(&self) -> Result<QemuExitReason, QemuExitError> {
        unsafe {
            QEMU_IS_RUNNING = true;
            self.run_inner();
            QEMU_IS_RUNNING = false;
        }

        let exit_reason = unsafe { libafl_get_exit_reason() };
        if exit_reason.is_null() {
            Err(QemuExitError::UnexpectedExit)
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
                libafl_qemu_sys::libafl_exit_reason_kind_CUSTOM_INSN => QemuExitReason::SyncExit,

                #[cfg(feature = "systemmode")]
                libafl_qemu_sys::libafl_exit_reason_kind_TIMEOUT => QemuExitReason::Timeout,

                _ => return Err(QemuExitError::UnknownKind),
            })
        }
    }

    #[must_use]
    #[allow(clippy::cast_possible_wrap)] // platform dependent
    #[expect(clippy::cast_sign_loss)]
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
    #[expect(clippy::cast_possible_wrap)]
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

    /// Read a value from a guest address, taking into account the potential indirections with the current CPU.
    pub fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), QemuRWError> {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .read_mem(addr, buf)
    }

    /// Read a value from a guest address, taking into account the potential indirections with the current CPU.
    pub fn read_mem_vec(&self, addr: GuestAddr, len: usize) -> Result<Vec<u8>, QemuRWError> {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .read_mem_vec(addr, len)
    }

    /// Write a value to a guest address, taking into account the potential indirections with the current CPU.
    pub fn write_mem(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), QemuRWError> {
        self.current_cpu()
            .unwrap_or_else(|| self.cpu_from_index(0))
            .write_mem(addr, buf)
    }

    /// Read a value from memory to a guest addr, taking into account the potential indirections with the current CPU.
    ///
    /// # Safety
    ///
    /// The read object should have the same layout as the type of val.
    /// No checked is performed to check whether the returned object makes sense or not.
    // TODO: Use sized array when const generics are stabilized.
    pub unsafe fn read_mem_val<T>(&self, addr: GuestAddr) -> Result<T, QemuRWError> {
        unsafe {
            // let mut val_buf: [u8; size_of::<T>()] = [0; size_of::<T>()];

            let val_buf: Vec<u8> = vec_init(size_of::<T>(), |buf| self.read_mem(addr, buf))?;

            Ok(ptr::read(val_buf.as_ptr() as *const T))
        }
    }

    /// Write a value to memory at a guest addr, taking into account the potential indirections with the current CPU.
    ///
    /// # Safety
    ///
    /// val will be used as parameter of [`slice::from_raw_parts`], and thus must enforce the same requirements.
    pub unsafe fn write_mem_val<T>(&self, addr: GuestAddr, val: &T) -> Result<(), QemuRWError> {
        unsafe {
            let val_buf: &[u8] =
                slice::from_raw_parts(ptr::from_ref(val) as *const u8, size_of::<T>());
            self.write_mem(addr, val_buf)?;

            Ok(())
        }
    }

    /// Read a value from a guest address.
    ///
    /// # Safety
    /// In usermode, this will read from a translated guest address.
    /// This may only be safely used for valid guest addresses.
    ///
    /// In any case, no check will be performed on the correctness of the operation.
    ///
    /// Please refer to [`CPU::read_mem`] for more details.
    pub unsafe fn read_mem_unchecked(&self, addr: GuestAddr, buf: &mut [u8]) {
        unsafe {
            self.current_cpu()
                .unwrap_or_else(|| self.cpu_from_index(0))
                .read_mem_unchecked(addr, buf);
        }
    }

    /// Write a value to a guest address.
    ///
    /// # Safety
    /// In usermode, this will write to a translated guest address.
    ///
    /// In any case, no check will be performed on the correctness of the operation.
    ///
    /// This may only be safely used for valid guest addresses.
    /// Please refer to [`CPU::write_mem`] for more details.
    pub unsafe fn write_mem_unchecked(&self, addr: GuestAddr, buf: &[u8]) {
        unsafe {
            self.current_cpu()
                .unwrap_or_else(|| self.cpu_from_index(0))
                .write_mem_unchecked(addr, buf);
        }
    }

    #[must_use]
    pub fn num_regs(&self) -> i32 {
        self.current_cpu().unwrap().num_regs()
    }

    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), QemuRWError>
    where
        T: Num + PartialOrd + Copy + Into<GuestReg>,
        R: Into<i32> + Clone,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Write))?
            .write_reg(reg, val)
    }

    pub fn read_reg<R>(&self, reg: R) -> Result<GuestReg, QemuRWError>
    where
        R: Into<i32> + Clone,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Read))?
            .read_reg(reg)
    }

    pub fn set_breakpoint(&self, addr: GuestAddr) {
        // Remove thumb bit encoded in addresses.
        // Since ARMv7, instructions are (half-)word aligned, so this is safe.
        // For ARMv6 and before, this could be wrong since SCTLR.U could be 0.
        // TODO: check precisely for architecture before doing this.
        #[cfg(target_arch = "arm")]
        let addr = { addr & !1 };

        unsafe {
            libafl_qemu_set_breakpoint(addr.into());
        }
    }

    pub fn remove_breakpoint(&self, addr: GuestAddr) {
        // Remove thumb bit encoded in addresses.
        // Since ARMv7, instructions are (half-)word aligned, so this is safe.
        // For ARMv6 and before, this could be wrong since SCTLR.U could be 0.
        // TODO: check precisely for architecture before doing this.
        #[cfg(target_arch = "arm")]
        let addr = { addr & !1 };

        unsafe {
            libafl_qemu_remove_breakpoint(addr.into());
        }
    }

    #[cfg(feature = "systemmode")]
    pub fn set_hw_breakpoint(&self, addr: GuestAddr) -> Result<(), Error> {
        let ret = unsafe { libafl_qemu_set_hw_breakpoint(addr.into()) };
        match ret {
            0 => Ok(()),
            errno => Err(Error::unsupported(format!(
                "Failed to set hw breakpoint errno: {errno}"
            ))),
        }
    }

    #[cfg(feature = "systemmode")]
    pub fn remove_hw_breakpoint(&self, addr: GuestAddr) -> Result<(), Error> {
        let ret = unsafe { libafl_qemu_remove_hw_breakpoint(addr.into()) };
        match ret {
            0 => Ok(()),
            errno => Err(Error::unsupported(format!(
                "Failed to set hw breakpoint errno: {errno}"
            ))),
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

    #[must_use]
    pub fn remove_hook(&self, id: &impl HookId, invalidate_block: bool) -> bool {
        id.remove(invalidate_block)
    }

    /// # Safety
    ///
    /// Calling this multiple times concurrently will access static variables and is unsafe.
    #[expect(clippy::type_complexity)]
    pub unsafe fn add_gdb_cmd(&self, callback: Box<dyn FnMut(&Self, &str) -> bool>) {
        unsafe {
            let fat: Box<FatPtr> = Box::new(transmute::<
                Box<dyn for<'a, 'b> FnMut(&'a Qemu, &'b str) -> bool>,
                FatPtr,
            >(callback));
            libafl_qemu_add_gdb_cmd(Some(gdb_cmd), ptr::from_ref(&*fat) as *mut c_void);
            let commands_ptr = &raw mut GDB_COMMANDS;
            (*commands_ptr).push(fat);
        }
    }

    pub fn gdb_reply(&self, output: &str) {
        unsafe { libafl_qemu_gdb_reply(output.as_bytes().as_ptr(), output.len()) };
    }

    #[must_use]
    pub fn host_page_size(&self) -> usize {
        unsafe { libafl_qemu_sys::libafl_qemu_host_page_size() }
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        unsafe { QEMU_IS_RUNNING }
    }

    /// Write the function arguments by following default calling convention.
    /// Assume that every arguments has integer/pointer type, otherwise the value
    /// may be stored at wrong place because of different rules for complex types.
    /// Note that the stack pointer register must point the top of the stack at the start
    /// of the called function, in case the argument is written in the stack.
    /// Support downward-growing stack only.
    /// If you need to specify a calling convention, use [`Self::write_function_arguments_with_cc`].
    pub fn write_function_arguments<T>(&mut self, val: &[T]) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg> + Copy,
    {
        self.write_function_arguments_with_cc(val, &CallingConvention::Default)
    }

    /// Write the function arguments by following calling convention `conv`.
    /// Assume that every arguments has integer/pointer type, otherwise the value
    /// may be stored at wrong place because of different rules for complex types.
    /// Note that the stack pointer register must point the top of the stack at the start
    /// of the called function, in case the argument is written in the stack.
    /// Support downward-growing stack only.
    pub fn write_function_arguments_with_cc<T>(
        &mut self,
        val: &[T],
        conv: &CallingConvention,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg> + Copy,
    {
        for (idx, elem) in val.iter().enumerate() {
            self.write_function_argument_with_cc(idx as u8, elem.to_owned(), conv.clone())?;
        }
        Ok(())
    }

    /// Read the function `idx` argument by following default calling convention.
    /// Assume that this argument and every prior arguments has integer/pointer type, otherwise
    /// it may return a wrong value because of different rules for complex types.
    /// Note that the stack pointer register must point the top of the stack at the start
    /// of the called function, in case the value is in the stack.
    /// Support downward-growing stack only.
    /// If you need to specify a calling convention, use [`Self::read_function_argument_with_cc`].
    pub fn read_function_argument(&self, idx: u8) -> Result<GuestReg, QemuRWError> {
        self.read_function_argument_with_cc(idx, CallingConvention::Default)
    }

    /// Write the function `val` into `idx` argument by following default calling convention.
    /// Assume that `val` and every prior arguments has integer/pointer type, otherwise the value
    /// may be stored at wrong place because of different rules for complex types.
    /// Note that the stack pointer register must point the top of the stack at the start
    /// of the called function, in case the argument is written in the stack.
    /// Support downward-growing stack only.
    /// If you need to specify a calling convention, use [`Self::write_function_argument_with_cc`].
    pub fn write_function_argument<T>(&self, idx: u8, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.write_function_argument_with_cc(idx, val, CallingConvention::Default)
    }
}

impl ArchExtras for Qemu {
    fn read_return_address(&self) -> Result<GuestReg, QemuRWError> {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Read))?
            .read_return_address()
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Write))?
            .write_return_address::<T>(val)
    }

    /// Read the function `idx` argument by following calling convention `conv`.
    /// Assume that this argument and every prior arguments has integer/pointer type, otherwise
    /// it may return a wrong value because of different rules for complex types.
    /// Note that the stack pointer register must point the top of the stack at the start
    /// of the called function, in case the value is in the stack.
    /// Support downward-growing stack only.
    fn read_function_argument_with_cc(
        &self,
        idx: u8,
        conv: CallingConvention,
    ) -> Result<GuestReg, QemuRWError> {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Read))?
            .read_function_argument_with_cc(idx, conv)
    }

    /// Write the function `val` into `idx` argument by following calling convention `conv`.
    /// Assume that `val` and every prior arguments has integer/pointer type, otherwise the value
    /// may be stored at wrong place because of different rules for complex types.
    /// Note that the stack pointer register must point the top of the stack at the start
    /// of the called function, in case the argument is written in the stack.
    /// Support downward-growing stack only.
    fn write_function_argument_with_cc<T>(
        &self,
        idx: u8,
        val: T,
        conv: CallingConvention,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.current_cpu()
            .ok_or(QemuRWError::current_cpu_not_found(QemuRWErrorKind::Write))?
            .write_function_argument_with_cc::<T>(idx, val, conv)
    }
}

// TODO: maybe include QEMU in the memory chunk to enable address translation and a more accurate implementation
impl PartialEq<Self> for GuestAddrKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (GuestAddrKind::Physical(paddr_self), GuestAddrKind::Physical(paddr_other)) => {
                paddr_self == paddr_other
            }
            (GuestAddrKind::Virtual(vaddr_self), GuestAddrKind::Virtual(vaddr_other)) => {
                vaddr_self == vaddr_other
            }
            _ => false,
        }
    }
}

// TODO: Check PartialEq comment, same idea
impl PartialOrd for GuestAddrKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (GuestAddrKind::Physical(paddr_self), GuestAddrKind::Physical(paddr_other)) => {
                paddr_self.partial_cmp(paddr_other)
            }
            (GuestAddrKind::Virtual(vaddr_self), GuestAddrKind::Virtual(vaddr_other)) => {
                vaddr_self.partial_cmp(vaddr_other)
            }
            _ => None,
        }
    }
}

impl QemuMemoryChunk {
    #[must_use]
    pub fn addr(&self) -> GuestAddrKind {
        self.addr
    }

    #[must_use]
    pub fn size(&self) -> GuestReg {
        self.size
    }

    #[must_use]
    pub fn phys(addr: GuestPhysAddr, size: GuestReg, cpu: Option<CPU>) -> Self {
        Self {
            addr: GuestAddrKind::Physical(addr),
            size,
            cpu,
        }
    }

    #[must_use]
    pub fn virt(addr: GuestVirtAddr, size: GuestReg, cpu: CPU) -> Self {
        Self {
            addr: GuestAddrKind::Virtual(addr),
            size,
            cpu: Some(cpu),
        }
    }

    #[must_use]
    pub fn get_slice(&self, range: &Range<GuestAddr>) -> Option<QemuMemoryChunk> {
        let new_addr = self.addr + range.start;
        let slice_size = range.clone().count();

        if new_addr + (slice_size as GuestUsize) >= self.addr + self.size.into() {
            return None;
        }

        Some(Self {
            addr: new_addr,
            size: slice_size as GuestReg,
            cpu: self.cpu,
        })
    }

    /// Returns the number of bytes effectively read.
    /// output will get chunked at `size` bytes.
    pub fn read(&self, qemu: Qemu, output: &mut [u8]) -> Result<GuestReg, QemuRWError> {
        let max_len: usize = self.size.try_into().unwrap();

        let output_sliced = if output.len() > max_len {
            &mut output[0..max_len]
        } else {
            output
        };

        match self.addr {
            GuestAddrKind::Physical(hwaddr) => {
                #[cfg(feature = "usermode")]
                {
                    // For now the default behaviour is to fall back to virtual addresses
                    qemu.read_mem(hwaddr.try_into().unwrap(), output_sliced)?;
                }
                #[cfg(feature = "systemmode")]
                unsafe {
                    qemu.read_phys_mem(hwaddr, output_sliced);
                }
            }
            GuestAddrKind::Virtual(vaddr) => unsafe {
                self.cpu
                    .as_ref()
                    .unwrap()
                    .read_mem_unchecked(vaddr.try_into().unwrap(), output_sliced);
            },
        }

        Ok(output_sliced.len().try_into().unwrap())
    }

    pub fn read_vec(&self, qemu: Qemu) -> Result<Vec<u8>, QemuRWError> {
        // # Safety
        // This is safe because we read exactly `self.size` bytes from QEMU.
        unsafe {
            vec_init(self.size as usize, |buf| {
                self.read(qemu, buf.as_slice_mut())?;

                Ok::<(), QemuRWError>(())
            })
        }
    }

    /// Returns the number of bytes effectively written.
    /// Input will get chunked at `size` bytes.
    pub fn write(&self, qemu: Qemu, input: &[u8]) -> Result<GuestReg, QemuRWError> {
        let max_len: usize = self.size.try_into().unwrap();

        let input_sliced = if input.len() > max_len {
            &input[0..max_len]
        } else {
            input
        };

        match self.addr {
            GuestAddrKind::Physical(hwaddr) => {
                #[cfg(feature = "usermode")]
                {
                    // For now the default behaviour is to fall back to virtual addresses
                    qemu.write_mem(hwaddr.try_into().unwrap(), input_sliced)?;
                }
                #[cfg(feature = "systemmode")]
                unsafe {
                    qemu.write_phys_mem(hwaddr, input_sliced);
                }
            }
            GuestAddrKind::Virtual(vaddr) => {
                self.cpu
                    .as_ref()
                    .unwrap()
                    .write_mem(vaddr.try_into().unwrap(), input_sliced)?;
            }
        }

        Ok(input_sliced.len().try_into().unwrap())
    }
}

#[cfg(feature = "python")]
pub mod pybind {
    use pyo3::{exceptions::PyValueError, prelude::*};

    use super::{GuestAddr, GuestUsize};

    static mut PY_GENERIC_HOOKS: Vec<(GuestAddr, PyObject)> = vec![];

    extern "C" fn py_generic_hook_wrapper(idx: u64, _pc: GuestAddr) {
        let obj = unsafe {
            let hooks = &raw mut PY_GENERIC_HOOKS;
            &(*hooks)[idx as usize].1
        };
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
        #[expect(clippy::needless_pass_by_value)]
        #[new]
        fn new(args: Vec<String>) -> PyResult<Qemu> {
            let qemu =
                super::Qemu::init(&args).map_err(|e| PyValueError::new_err(format!("{e}")))?;

            Ok(Qemu { qemu })
        }

        fn run(&self) {
            unsafe {
                self.qemu.run().unwrap();
            }
        }

        fn write_mem(&self, addr: GuestAddr, buf: &[u8]) {
            self.qemu
                .write_mem(addr, buf)
                .expect("Write to memory failed.");
        }

        fn read_mem(&self, addr: GuestAddr, size: usize) -> Vec<u8> {
            let mut buf = vec![0; size];
            self.qemu
                .read_mem(addr, &mut buf)
                .expect("Read to memory failed.");
            buf
        }

        fn num_regs(&self) -> i32 {
            self.qemu.num_regs()
        }

        fn write_reg(&self, reg: i32, val: GuestUsize) -> PyResult<()> {
            self.qemu
                .write_reg(reg, val)
                .map_err(|_| PyValueError::new_err("write register error"))
        }

        fn read_reg(&self, reg: i32) -> PyResult<GuestUsize> {
            self.qemu
                .read_reg(reg)
                .map_err(|_| PyValueError::new_err("read register error"))
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

        fn flush_jit(&self) {
            self.qemu.flush_jit();
        }

        /// # Safety
        /// Removes a hooke from `PY_GENERIC_HOOKS` -> may not be called concurrently!
        unsafe fn set_hook(&self, addr: GuestAddr, hook: PyObject) {
            unsafe {
                let hooks = &raw mut PY_GENERIC_HOOKS;
                let idx = (*hooks).len();
                (*hooks).push((addr, hook));
                self.qemu.hooks().add_instruction_hooks(
                    idx as u64,
                    addr,
                    py_generic_hook_wrapper,
                    true,
                );
            }
        }

        /// # Safety
        /// Removes a hooke from `PY_GENERIC_HOOKS` -> may not be called concurrently!
        unsafe fn remove_hooks_at(&self, addr: GuestAddr) -> usize {
            unsafe {
                let hooks = &raw mut PY_GENERIC_HOOKS;
                (*hooks).retain(|(a, _)| *a != addr);
            }
            self.qemu.hooks().remove_instruction_hooks_at(addr, true)
        }
    }
}
