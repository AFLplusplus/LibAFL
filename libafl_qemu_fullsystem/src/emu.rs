//! Expose QEMU user `LibAFL` C api to Rust

use core::{
    convert::Into,
    ptr::{addr_of, addr_of_mut, null},
};
use libafl::inputs::Input;
use libafl::monitors::Monitor;
use libafl::events::SimpleEventManager;
use libafl::events::EventFirer;
use libafl::events::EventManagerId;
use libafl::events::ProgressReporter;
use libafl::events::HasEventManagerId;
use libafl::events::EventManager;
use libafl::events::EventProcessor;
use libafl::Error;
use libafl::events::EventRestarter;
use libafl::events::Event;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use num_traits::Num;
use std::{slice::from_raw_parts, str::from_utf8_unchecked};
use strum_macros::EnumIter;

#[cfg(not(any(cpu_target = "x86_64", cpu_target = "aarch64")))]
/// `GuestAddr` is u32 for 32-bit targets
pub type GuestAddr = u32;

#[cfg(any(cpu_target = "x86_64", cpu_target = "aarch64"))]
/// `GuestAddr` is u64 for 64-bit targets
pub type GuestAddr = u64;

pub type GuestUsize = GuestAddr;

#[cfg(feature = "python")]
use pyo3::{prelude::*, PyIterProtocol};

pub const SKIP_EXEC_HOOK: u64 = u64::MAX;

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter, PartialEq)]
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

pub static mut DISABLE_EDGE_GEN: bool = false;

#[no_mangle]
pub fn libafl_enable_edge_gen() {
    unsafe {
        DISABLE_EDGE_GEN = false;
    }
}

#[no_mangle]
pub fn libafl_disable_edge_gen() {
    unsafe {
        DISABLE_EDGE_GEN = true;
    }
}

extern "C" {
    fn libafl_qemu_write_reg(reg: i32, val: *const u8) -> i32;
    fn libafl_qemu_read_reg(reg: i32, val: *mut u8) -> i32;
    fn libafl_qemu_num_regs() -> i32;
    fn libafl_qemu_set_hook(addr: u64, callback: extern "C" fn(u64), val: u64) -> i32;
    fn libafl_qemu_remove_hook(addr: u64) -> i32;
    fn libafl_load_snapshot_restart();

    fn strlen(s: *const u8) -> usize;

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
}


use serde::Serialize;

pub struct SimpleQemuRestartingEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    /// The actual simple event mgr
    simple_event_mgr: SimpleEventManager<I, MT>,
}

impl<I, MT> EventFirer<I> for SimpleQemuRestartingEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    fn fire<S>(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        self.simple_event_mgr.fire(_state, event)
    }
}


impl<I, S, MT> EventRestarter<S> for SimpleQemuRestartingEventManager<I, MT>
where
    I: Input,
    S: Serialize,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    /// Reset the single page (we reuse it over and over from pos 0), then send the current state to the next runner.
    fn on_restart(&mut self, _state: &mut S) -> Result<(), Error> {
        // First, reset the page to 0 so the next iteration can read read from the beginning of this page
        //self.staterestorer.reset();
        //self.staterestorer.save(state)
        //unimplemented!("call here to QEMU and load snapshot")
        unsafe {
            libafl_disable_edge_gen();
            libafl_load_snapshot_restart()
        };
        Ok(())
    }
}


impl<E, I, S, MT, Z> EventProcessor<E, I, S, Z> for SimpleQemuRestartingEventManager<I, MT>
where
    I: Input,
    S: Serialize,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
    fn process(&mut self, fuzzer: &mut Z, state: &mut S, executor: &mut E) -> Result<usize, Error> {
        self.simple_event_mgr.process(fuzzer, state, executor)
    }
}

impl<E, I, S, MT, Z> EventManager<E, I, S, Z> for SimpleQemuRestartingEventManager<I, MT>
where
    I: Input,
    S: Serialize,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
}


impl<I, MT> HasEventManagerId for SimpleQemuRestartingEventManager<I, MT>
where
    I: Input,
    MT: Monitor,
{
    fn mgr_id(&self) -> EventManagerId {
        self.simple_event_mgr.mgr_id()
    }
}


impl<I, MT> ProgressReporter<I> for SimpleQemuRestartingEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //CE: CustomEvent<I, OT>,
{
}


#[allow(clippy::type_complexity, clippy::too_many_lines)]
impl<I, MT> SimpleQemuRestartingEventManager<I, MT>
where
    I: Input,
    MT: Monitor, //TODO CE: CustomEvent,
{
    /// Creates a new [`SimpleEventManager`].
    pub fn new(monitor: MT) -> Self {
        Self {
            simple_event_mgr: SimpleEventManager::new(monitor),
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
            assert!(
                !EMULATOR_IS_INITIALIZED,
                "Only an instance of Emulator is permitted"
            );
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
        unsafe {
            EMULATOR_IS_INITIALIZED = true;
        }
        Emulator { _private: () }
    }

    #[must_use]
    pub fn new_empty() -> Emulator {
        unsafe {
            EMULATOR_IS_INITIALIZED = true;
        }
        Emulator { _private: () }
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
        let success = unsafe { libafl_qemu_write_reg(reg, addr_of!(val) as *const u8) };
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
        let success = unsafe { libafl_qemu_read_reg(reg, addr_of_mut!(val) as *mut u8) };
        if success == 0 {
            Err(format!("Failed to read register {}", reg))
        } else {
            Ok(val)
        }
    }

    pub fn set_hook(&self, addr: GuestAddr, callback: extern "C" fn(u64), val: u64) {
        unsafe {
            libafl_qemu_set_hook(addr.into(), callback, val);
        }
    }

    pub fn remove_hook(&self, addr: GuestAddr) {
        unsafe {
            libafl_qemu_remove_hook(addr.into());
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

}
