//! Higher-level abstraction of [`Qemu`]
//!
//! [`Emulator`] is built above [`Qemu`] and provides convenient abstractions.

use core::{
    fmt::{self, Debug, Display, Formatter},
    marker::PhantomData,
};
use std::{cell::RefCell, ops::Add, pin::Pin};

use hashbrown::HashMap;
use libafl::{executors::ExitKind, inputs::UsesInput, observers::ObserversTuple};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestUsize, GuestVirtAddr};

use crate::{
    breakpoint::{Breakpoint, BreakpointId},
    command::{CommandError, CommandManager},
    modules::EmulatorModuleTuple,
    sync_exit::SyncExit,
    Qemu, QemuExitError, QemuExitReason, QemuInitError, QemuMemoryChunk, QemuShutdownCause, Regs,
    CPU,
};

mod hooks;
pub use hooks::*;

mod builder;
pub use builder::*;

mod drivers;
pub use drivers::*;

mod snapshot;
pub use snapshot::*;

#[cfg(emulation_mode = "usermode")]
mod usermode;

#[cfg(emulation_mode = "systemmode")]
mod systemmode;
#[cfg(emulation_mode = "systemmode")]
pub use systemmode::*;

use crate::modules::StdInstrumentationFilter;

#[derive(Clone, Copy)]
pub enum GuestAddrKind {
    Physical(GuestPhysAddr),
    Virtual(GuestVirtAddr),
}

#[derive(Debug, Clone)]
pub enum EmulatorExitResult<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    QemuExit(QemuShutdownCause),   // QEMU ended for some reason.
    Breakpoint(Breakpoint<CM, S>), // Breakpoint triggered. Contains the address of the trigger.
    SyncExit(SyncExit<CM, S>), // Synchronous backdoor: The guest triggered a backdoor and should return to LibAFL.
}

#[derive(Debug, Clone)]
pub enum EmulatorExitError {
    UnknownKind,
    UnexpectedExit,
    CommandError(CommandError),
    BreakpointNotFound(GuestAddr),
}

#[derive(Debug, Clone)]
pub struct InputLocation {
    mem_chunk: QemuMemoryChunk,
    cpu: CPU,
    ret_register: Option<Regs>,
}

#[derive(Debug)]
pub struct Emulator<CM, EDT, ET, S, SM>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    snapshot_manager: SM,
    modules: Pin<Box<EmulatorModules<ET, S>>>,
    command_manager: CM,
    drivers: Option<EDT>,
    breakpoints_by_addr: RefCell<HashMap<GuestAddr, Breakpoint<CM, S>>>, // TODO: change to RC here
    breakpoints_by_id: RefCell<HashMap<BreakpointId, Breakpoint<CM, S>>>,
    qemu: Qemu,
    first_exec: bool,
    _phantom: PhantomData<(ET, S, SM)>,
}

impl<CM, S> EmulatorDriverResult<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    #[must_use]
    #[allow(clippy::match_wildcard_for_single_variants)]
    pub fn end_of_run(&self) -> Option<ExitKind> {
        match self {
            EmulatorDriverResult::EndOfRun(exit_kind) => Some(*exit_kind),
            _ => None,
        }
    }
}

impl<CM, S> TryFrom<EmulatorDriverResult<CM, S>> for ExitKind
where
    CM: CommandManager<S> + Debug,
    S: UsesInput + Debug,
{
    type Error = String;

    fn try_from(value: EmulatorDriverResult<CM, S>) -> Result<Self, Self::Error> {
        match value {
            EmulatorDriverResult::ReturnToHarness(unhandled_qemu_exit) => {
                Err(format!("Unhandled QEMU exit: {:?}", &unhandled_qemu_exit))
            }
            EmulatorDriverResult::EndOfRun(exit_kind) => Ok(exit_kind),
        }
    }
}

impl Debug for GuestAddrKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestAddrKind::Physical(paddr) => write!(f, "vaddr {paddr:x}"),
            GuestAddrKind::Virtual(vaddr) => write!(f, "paddr {vaddr:x}"),
        }
    }
}

impl Add<GuestUsize> for GuestAddrKind {
    type Output = Self;

    fn add(self, rhs: GuestUsize) -> Self::Output {
        match self {
            GuestAddrKind::Physical(paddr) => GuestAddrKind::Physical(paddr + rhs as GuestPhysAddr),
            GuestAddrKind::Virtual(vaddr) => GuestAddrKind::Virtual(vaddr + rhs as GuestVirtAddr),
        }
    }
}

impl Display for GuestAddrKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuestAddrKind::Physical(phys_addr) => write!(f, "hwaddr 0x{phys_addr:x}"),
            GuestAddrKind::Virtual(virt_addr) => write!(f, "vaddr 0x{virt_addr:x}"),
        }
    }
}

impl From<SnapshotManagerError> for EmulatorDriverError {
    fn from(sm_error: SnapshotManagerError) -> Self {
        EmulatorDriverError::SMError(sm_error)
    }
}

impl From<SnapshotManagerCheckError> for EmulatorDriverError {
    fn from(sm_check_error: SnapshotManagerCheckError) -> Self {
        EmulatorDriverError::SMCheckError(sm_check_error)
    }
}

impl InputLocation {
    #[must_use]
    pub fn new(mem_chunk: QemuMemoryChunk, cpu: CPU, ret_register: Option<Regs>) -> Self {
        Self {
            mem_chunk,
            cpu,
            ret_register,
        }
    }
}

impl From<EmulatorExitError> for EmulatorDriverError {
    fn from(error: EmulatorExitError) -> Self {
        EmulatorDriverError::QemuExitReasonError(error)
    }
}

impl From<CommandError> for EmulatorDriverError {
    fn from(error: CommandError) -> Self {
        EmulatorDriverError::CommandError(error)
    }
}

impl<CM, S> Display for EmulatorExitResult<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            EmulatorExitResult::QemuExit(shutdown_cause) => write!(f, "End: {shutdown_cause:?}"),
            EmulatorExitResult::Breakpoint(bp) => write!(f, "{}", bp),
            EmulatorExitResult::SyncExit(_sync_exit) => {
                write!(f, "Sync exit")
            }
        }
    }
}

impl From<CommandError> for EmulatorExitError {
    fn from(error: CommandError) -> Self {
        EmulatorExitError::CommandError(error)
    }
}

impl<CM, EDT, ET, S, SM> Emulator<CM, EDT, ET, S, SM>
where
    CM: CommandManager<S>,
    ET: Unpin,
    S: UsesInput + Unpin,
{
    pub fn modules_mut(&mut self) -> &mut EmulatorModules<ET, S> {
        self.modules.as_mut().get_mut()
    }
}

impl<CM, EDT, ET, S, SM> Emulator<CM, EDT, ET, S, SM>
where
    CM: CommandManager<S>,
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn new(
        qemu_args: &[String],
        modules: ET,
        drivers: EDT,
        snapshot_manager: SM,
        command_manager: CM,
    ) -> Result<Self, QemuInitError> {
        let qemu = Qemu::init(qemu_args)?;

        Self::new_with_qemu(qemu, modules, drivers, snapshot_manager, command_manager)
    }

    pub fn new_with_qemu(
        qemu: Qemu,
        modules: ET,
        drivers: EDT,
        snapshot_manager: SM,
        command_manager: CM,
    ) -> Result<Self, QemuInitError> {
        Ok(Emulator {
            modules: EmulatorModules::new(qemu, modules),
            command_manager,
            snapshot_manager,
            drivers: Some(drivers),
            breakpoints_by_addr: RefCell::new(HashMap::new()),
            breakpoints_by_id: RefCell::new(HashMap::new()),
            first_exec: true,
            _phantom: PhantomData,
            qemu,
        })
    }

    pub fn first_exec_all(&mut self) {
        if self.first_exec {
            self.modules.first_exec_all();
            self.first_exec = false;
        }
    }

    pub fn pre_exec_all(&mut self, input: &S::Input) {
        self.modules.pre_exec_all(input);
    }

    pub fn post_exec_all<OT>(
        &mut self,
        input: &S::Input,
        observers: &mut OT,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S>,
    {
        self.modules.post_exec_all(input, observers, exit_kind);
    }
}

impl<CM, EDT, ET, S, SM> Emulator<CM, EDT, ET, S, SM>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    pub fn modules(&self) -> &EmulatorModules<ET, S> {
        &self.modules
    }

    #[must_use]
    pub fn qemu(&self) -> Qemu {
        self.qemu
    }

    #[must_use]
    pub fn drivers(&self) -> &EDT {
        self.drivers.as_ref().unwrap()
    }

    #[must_use]
    pub fn drivers_mut(&mut self) -> &mut EDT {
        self.drivers.as_mut().unwrap()
    }

    #[must_use]
    pub fn snapshot_manager(&self) -> &SM {
        &self.snapshot_manager
    }

    #[must_use]
    pub fn snapshot_manager_mut(&mut self) -> &mut SM {
        &mut self.snapshot_manager
    }
}

impl<CM, EDT, ET, S, SM> Emulator<CM, EDT, ET, S, SM>
where
    ET: StdInstrumentationFilter + Unpin,
    CM: CommandManager<S> + Clone,
    EDT: EmulatorDriverTuple<CM, S, SM>,
    S: UsesInput + Clone,
{
    /// This function will run the emulator until the exit handler decides to stop the execution for
    /// whatever reason, depending on the choosen handler.
    /// It is a higher-level abstraction of [`Emulator::run`] that will take care of some part of the runtime logic,
    /// returning only when something interesting happen.
    ///
    /// # Safety
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run(
        &mut self,
        input: &S::Input,
    ) -> Result<EmulatorDriverResult<CM, S>, EmulatorDriverError> {
        let mut drivers = self.drivers.take().unwrap();

        loop {
            // Insert input if the location is already known
            drivers.pre_exec_all(self, input);

            // Run QEMU
            let mut exit_reason = self.run_qemu();

            // Handle QEMU exit
            if let Some(exit_handler_result) =
                drivers.post_exec_all(self, &mut exit_reason, input)?
            {
                self.drivers = Some(drivers);
                return Ok(exit_handler_result);
            }
        }
    }

    /// This function will run the emulator until the next breakpoint, or until finish.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run_qemu(&self) -> Result<EmulatorExitResult<CM, S>, EmulatorExitError> {
        match self.qemu.run() {
            Ok(qemu_exit_reason) => Ok(match qemu_exit_reason {
                QemuExitReason::End(qemu_shutdown_cause) => {
                    EmulatorExitResult::QemuExit(qemu_shutdown_cause)
                }
                QemuExitReason::Breakpoint(bp_addr) => {
                    let bp = self
                        .breakpoints_by_addr
                        .borrow()
                        .get(&bp_addr)
                        .ok_or(EmulatorExitError::BreakpointNotFound(bp_addr))?
                        .clone();
                    EmulatorExitResult::Breakpoint(bp.clone())
                }
                QemuExitReason::SyncExit => EmulatorExitResult::SyncExit(SyncExit::new(
                    self.command_manager.parse(self.qemu)?,
                )),
            }),
            Err(qemu_exit_reason_error) => Err(match qemu_exit_reason_error {
                QemuExitError::UnexpectedExit => EmulatorExitError::UnexpectedExit,
                QemuExitError::UnknownKind => EmulatorExitError::UnknownKind,
            }),
        }
    }
}

#[allow(clippy::unused_self)]
impl<CM, EH, ET, S, SM> Emulator<CM, EH, ET, S, SM>
where
    CM: CommandManager<S> + Clone,
    S: UsesInput + Clone,
{
    pub fn add_breakpoint(&self, mut bp: Breakpoint<CM, S>, enable: bool) -> BreakpointId {
        if enable {
            bp.enable(self.qemu);
        }

        let bp_id = bp.id();
        let bp_addr = bp.addr();

        assert!(
            self.breakpoints_by_addr
                .borrow_mut()
                .insert(bp_addr, bp.clone())
                .is_none(),
            "Adding multiple breakpoints at the same address"
        );

        assert!(
            self.breakpoints_by_id
                .borrow_mut()
                .insert(bp_id, bp)
                .is_none(),
            "Adding the same breakpoint multiple times"
        );

        bp_id
    }

    pub fn remove_breakpoint(&self, bp_id: BreakpointId) {
        let bp_addr = {
            let mut bp_map = self.breakpoints_by_id.borrow_mut();
            let bp = bp_map.get_mut(&bp_id).expect("Did not find the breakpoint");
            bp.disable(self.qemu);
            bp.addr()
        };

        self.breakpoints_by_id
            .borrow_mut()
            .remove(&bp_id)
            .expect("Could not remove bp");
        self.breakpoints_by_addr
            .borrow_mut()
            .remove(&bp_addr)
            .expect("Could not remove bp");
    }
}
