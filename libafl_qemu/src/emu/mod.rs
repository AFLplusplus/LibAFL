//! Higher-level abstraction of [`Qemu`]
//!
//! [`Emulator`] is built above [`Qemu`] and provides convenient abstractions.

use core::{
    fmt::{self, Debug, Display, Formatter},
    marker::PhantomData,
};
use std::{
    cell::{OnceCell, Ref, RefCell, RefMut},
    hash::Hash,
    ops::Add,
    pin::Pin,
    rc::Rc,
};

use hashbrown::HashMap;
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
    observers::ObserversTuple,
};
use libafl_bolts::os::unix_signals::Signal;
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestUsize, GuestVirtAddr};
use typed_builder::TypedBuilder;

use crate::{
    breakpoint::{Breakpoint, BreakpointId},
    command::{CommandError, CommandManager, InputCommand, IsCommand},
    modules::EmulatorModuleTuple,
    sync_exit::SyncExit,
    Qemu, QemuExitError, QemuExitReason, QemuInitError, QemuMemoryChunk, QemuShutdownCause,
    QemuSnapshotCheckResult, Regs, CPU,
};

mod hooks;
pub use hooks::*;

#[cfg(emulation_mode = "usermode")]
mod usermode;

#[cfg(emulation_mode = "systemmode")]
mod systemmode;
#[cfg(emulation_mode = "systemmode")]
pub use systemmode::*;

type CommandRef<CM, E, ET, S> = Rc<dyn IsCommand<CM, E, ET, S>>;
type BreakpointMutRef<CM, E, ET, S> = Rc<RefCell<Breakpoint<CM, E, ET, S>>>;

pub trait IsSnapshotManager: Clone + Debug {
    fn save(&mut self, qemu: Qemu) -> SnapshotId;
    fn restore(&mut self, snapshot_id: &SnapshotId, qemu: Qemu)
        -> Result<(), SnapshotManagerError>;
    fn do_check(
        &self,
        reference_snapshot_id: &SnapshotId,
        qemu: Qemu,
    ) -> Result<QemuSnapshotCheckResult, SnapshotManagerError>;

    fn check(
        &self,
        reference_snapshot_id: &SnapshotId,
        qemu: Qemu,
    ) -> Result<(), SnapshotManagerCheckError> {
        let check_result = self
            .do_check(reference_snapshot_id, qemu)
            .map_err(SnapshotManagerCheckError::SnapshotManagerError)?;

        if check_result == QemuSnapshotCheckResult::default() {
            Ok(())
        } else {
            Err(SnapshotManagerCheckError::SnapshotCheckError(check_result))
        }
    }
}

pub trait EmulatorExitHandler<ET, S>: Sized + Debug + Clone
where
    S: UsesInput,
{
    fn qemu_pre_exec<CM: CommandManager<Self, ET, S>>(
        emu: &mut Emulator<CM, Self, ET, S>,
        input: &S::Input,
    );

    fn qemu_post_exec<CM: CommandManager<Self, ET, S>>(
        emu: &mut Emulator<CM, Self, ET, S>,
        exit_reason: Result<EmulatorExitResult<CM, Self, ET, S>, EmulatorExitError>,
        input: &S::Input,
    ) -> Result<Option<ExitHandlerResult<CM, Self, ET, S>>, ExitHandlerError>;
}

#[derive(Clone, Copy)]
pub enum GuestAddrKind {
    Physical(GuestPhysAddr),
    Virtual(GuestVirtAddr),
}

#[derive(Debug, Clone)]
pub enum EmulatorExitResult<CM, EH, ET, S>
where
    S: UsesInput,
{
    QemuExit(QemuShutdownCause), // QEMU ended for some reason.
    Breakpoint(Rc<RefCell<Breakpoint<CM, EH, ET, S>>>), // Breakpoint triggered. Contains the address of the trigger.
    SyncExit(Rc<RefCell<SyncExit<CM, EH, ET, S>>>), // Synchronous backdoor: The guest triggered a backdoor and should return to LibAFL.
}

#[derive(Debug, Clone)]
pub enum EmulatorExitError {
    UnknownKind,
    UnexpectedExit,
    CommandError(CommandError),
    BreakpointNotFound(GuestAddr),
}

#[derive(Debug, Clone)]
pub enum ExitHandlerError {
    QemuExitReasonError(EmulatorExitError),
    SMError(SnapshotManagerError),
    SMCheckError(SnapshotManagerCheckError),
    CommandError(CommandError),
    UnhandledSignal(Signal),
    MultipleSnapshotDefinition,
    MultipleInputDefinition,
    SnapshotNotFound,
}

#[derive(Debug, Clone)]
pub enum ExitHandlerResult<CM, EH, ET, S>
where
    S: UsesInput,
{
    ReturnToHarness(EmulatorExitResult<CM, EH, ET, S>), // Return to the harness immediately. Can happen at any point of the run when the handler is not supposed to handle a request.
    EndOfRun(ExitKind), // The run is over and the emulator is ready for the next iteration.
}

#[derive(Debug, Clone)]
pub enum SnapshotManagerError {
    SnapshotIdNotFound(SnapshotId),
    MemoryInconsistencies(u64),
}

#[derive(Debug, Clone)]
pub enum SnapshotManagerCheckError {
    SnapshotManagerError(SnapshotManagerError),
    SnapshotCheckError(QemuSnapshotCheckResult),
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct SnapshotId {
    id: u64,
}

/// Special kind of Exit handler with no data embedded.
/// As a result, it is safe to transmute from any `Emulator` implementing `EmuExitHandler` to this one,
/// since it won't use any data which could cause type confusion.
#[derive(Clone, Debug)]
pub struct NopEmulatorExitHandler;
impl<ET, S> EmulatorExitHandler<ET, S> for NopEmulatorExitHandler
where
    S: UsesInput,
{
    fn qemu_pre_exec<CM: CommandManager<Self, ET, S>>(
        _: &mut Emulator<CM, Self, ET, S>,
        _: &S::Input,
    ) {
    }

    fn qemu_post_exec<CM: CommandManager<Self, ET, S>>(
        _: &mut Emulator<CM, Self, ET, S>,
        exit_reason: Result<EmulatorExitResult<CM, Self, ET, S>, EmulatorExitError>,
        _: &S::Input,
    ) -> Result<Option<ExitHandlerResult<CM, Self, ET, S>>, ExitHandlerError> {
        match exit_reason {
            Ok(reason) => Ok(Some(ExitHandlerResult::ReturnToHarness(reason))),
            Err(error) => Err(error)?,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputLocation {
    mem_chunk: QemuMemoryChunk,
    cpu: CPU,
    ret_register: Option<Regs>,
}

/// Synchronous Exit handler maintaining only one snapshot.
#[derive(Debug, Clone, TypedBuilder)]
pub struct StdEmulatorExitHandler<SM> {
    snapshot_manager: RefCell<SM>,
    #[builder(default)]
    snapshot_id: OnceCell<SnapshotId>,
    #[builder(default)]
    input_location: OnceCell<InputLocation>,
}

// TODO: Replace TypedBuilder by something better, it does not work correctly with default and
// inter-dependent fields.
#[derive(Debug, TypedBuilder)]
pub struct Emulator<CM, EH, ET, S>
where
    S: UsesInput,
{
    modules: Pin<Box<EmulatorModules<ET, S>>>,
    command_manager: CM,
    exit_handler: RefCell<EH>,
    #[builder(default)]
    breakpoints_by_addr: RefCell<HashMap<GuestAddr, BreakpointMutRef<CM, EH, ET, S>>>,
    #[builder(default)]
    breakpoints_by_id: RefCell<HashMap<BreakpointId, BreakpointMutRef<CM, EH, ET, S>>>,
    #[builder(setter(transform = |args: &[String], env: &[(String, String)]| Qemu::init(args, env).unwrap()))]
    qemu: Qemu,
    first_exec: bool,
    _phantom: PhantomData<(ET, S)>,
}

impl<CM, EH, ET, S> ExitHandlerResult<CM, EH, ET, S>
where
    S: UsesInput,
{
    #[must_use]
    #[allow(clippy::match_wildcard_for_single_variants)]
    pub fn end_of_run(&self) -> Option<ExitKind> {
        match self {
            ExitHandlerResult::EndOfRun(exit_kind) => Some(*exit_kind),
            _ => None,
        }
    }
}

impl<CM, EH, ET, S> TryFrom<ExitHandlerResult<CM, EH, ET, S>> for ExitKind
where
    CM: Debug,
    EH: Debug,
    ET: Debug,
    S: UsesInput + Debug,
{
    type Error = String;

    fn try_from(value: ExitHandlerResult<CM, EH, ET, S>) -> Result<Self, Self::Error> {
        match value {
            ExitHandlerResult::ReturnToHarness(unhandled_qemu_exit) => {
                Err(format!("Unhandled QEMU exit: {:?}", &unhandled_qemu_exit))
            }
            ExitHandlerResult::EndOfRun(exit_kind) => Ok(exit_kind),
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

impl From<SnapshotManagerError> for ExitHandlerError {
    fn from(sm_error: SnapshotManagerError) -> Self {
        ExitHandlerError::SMError(sm_error)
    }
}

impl From<SnapshotManagerCheckError> for ExitHandlerError {
    fn from(sm_check_error: SnapshotManagerCheckError) -> Self {
        ExitHandlerError::SMCheckError(sm_check_error)
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

impl<SM> StdEmulatorExitHandler<SM> {
    pub fn new(snapshot_manager: SM) -> Self {
        Self {
            snapshot_manager: RefCell::new(snapshot_manager),
            snapshot_id: OnceCell::new(),
            input_location: OnceCell::new(),
        }
    }

    pub fn set_input_location(&self, input_location: InputLocation) -> Result<(), InputLocation> {
        self.input_location.set(input_location)
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
impl<ET, S, SM> EmulatorExitHandler<ET, S> for StdEmulatorExitHandler<SM>
where
    S: UsesInput,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn qemu_pre_exec<CM: CommandManager<Self, ET, S>>(
        emu: &mut Emulator<CM, Self, ET, S>,
        input: &S::Input,
    ) {
        let input_location = {
            let exit_handler = emu.exit_handler.borrow();
            exit_handler.input_location.get().cloned()
        };

        if let Some(input_location) = input_location {
            let input_command =
                InputCommand::new(input_location.mem_chunk.clone(), input_location.cpu);

            input_command
                .run(emu, input, input_location.ret_register)
                .unwrap();
        }
    }

    fn qemu_post_exec<CM: CommandManager<Self, ET, S>>(
        emu: &mut Emulator<CM, Self, ET, S>,
        exit_reason: Result<EmulatorExitResult<CM, Self, ET, S>, EmulatorExitError>,
        input: &S::Input,
    ) -> Result<Option<ExitHandlerResult<CM, Self, ET, S>>, ExitHandlerError> {
        let exit_handler = emu.exit_handler().borrow_mut();
        let qemu = emu.qemu();

        let mut exit_reason = match exit_reason {
            Ok(exit_reason) => exit_reason,
            Err(exit_error) => match exit_error {
                EmulatorExitError::UnexpectedExit => {
                    if let Some(snapshot_id) = exit_handler.snapshot_id.get() {
                        exit_handler
                            .snapshot_manager
                            .borrow_mut()
                            .restore(snapshot_id, qemu)?;
                    }
                    return Ok(Some(ExitHandlerResult::EndOfRun(ExitKind::Crash)));
                }
                _ => Err(exit_error)?,
            },
        };

        #[allow(clippy::type_complexity)]
        let (command, ret_reg): (Option<CommandRef<CM, Self, ET, S>>, Option<Regs>) =
            match &mut exit_reason {
                EmulatorExitResult::QemuExit(shutdown_cause) => match shutdown_cause {
                    QemuShutdownCause::HostSignal(signal) => {
                        signal.handle();
                        return Err(ExitHandlerError::UnhandledSignal(*signal));
                    }
                    QemuShutdownCause::GuestPanic => {
                        return Ok(Some(ExitHandlerResult::EndOfRun(ExitKind::Crash)))
                    }
                    _ => panic!("Unhandled QEMU shutdown cause: {shutdown_cause:?}."),
                },
                EmulatorExitResult::Breakpoint(bp) => (bp.borrow_mut().trigger(qemu), None),
                EmulatorExitResult::SyncExit(sync_backdoor) => {
                    let sync_backdoor = sync_backdoor.borrow();
                    let command = sync_backdoor.command();
                    (Some(command), Some(sync_backdoor.ret_reg()))
                }
            };

        // manually drop ref cell here to avoid keeping it alive in cmd.
        drop(exit_handler);

        if let Some(cmd) = command {
            cmd.run(emu, input, ret_reg)
        } else {
            Ok(Some(ExitHandlerResult::ReturnToHarness(exit_reason)))
        }
    }
}

impl From<EmulatorExitError> for ExitHandlerError {
    fn from(error: EmulatorExitError) -> Self {
        ExitHandlerError::QemuExitReasonError(error)
    }
}

impl From<CommandError> for ExitHandlerError {
    fn from(error: CommandError) -> Self {
        ExitHandlerError::CommandError(error)
    }
}

impl<CM, EH, ET, S> Display for EmulatorExitResult<CM, EH, ET, S>
where
    S: UsesInput,
{
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            EmulatorExitResult::QemuExit(shutdown_cause) => write!(f, "End: {shutdown_cause:?}"),
            EmulatorExitResult::Breakpoint(bp) => write!(f, "{}", bp.borrow()),
            EmulatorExitResult::SyncExit(sync_exit) => {
                write!(f, "Sync exit: {}", sync_exit.borrow())
            }
        }
    }
}

impl From<CommandError> for EmulatorExitError {
    fn from(error: CommandError) -> Self {
        EmulatorExitError::CommandError(error)
    }
}

impl<CM, EH, ET, S> Emulator<CM, EH, ET, S>
where
    ET: Unpin,
    S: UsesInput + Unpin,
{
    pub fn modules_mut(&mut self) -> &mut EmulatorModules<ET, S> {
        self.modules.as_mut().get_mut()
    }
}

impl<CM, EH, ET, S> Emulator<CM, EH, ET, S>
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn new(
        args: &[String],
        env: &[(String, String)],
        modules: ET,
        exit_handler: EH,
        command_manager: CM,
    ) -> Result<Self, QemuInitError> {
        let qemu = Qemu::init(args, env)?;

        Self::new_with_qemu(qemu, modules, exit_handler, command_manager)
    }

    pub fn new_with_qemu(
        qemu: Qemu,
        modules: ET,
        exit_handler: EH,
        command_manager: CM,
    ) -> Result<Self, QemuInitError> {
        Ok(Emulator {
            modules: EmulatorModules::new(qemu, modules),
            command_manager,
            exit_handler: RefCell::new(exit_handler),
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

impl<CM, EH, ET, S> Emulator<CM, EH, ET, S>
where
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
    pub fn exit_handler(&self) -> &RefCell<EH> {
        &self.exit_handler
    }
}

impl<CM, EH, ET, S> Emulator<CM, EH, ET, S>
where
    EH: EmulatorExitHandler<ET, S>,
    CM: CommandManager<EH, ET, S>,
    S: UsesInput,
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
    ) -> Result<ExitHandlerResult<CM, EH, ET, S>, ExitHandlerError> {
        loop {
            // if self.first_exec {
            //     self.modules_mut().first_exec_all();
            //     self.first_exec = false;
            // }

            // // First run modules callback functions
            // self.modules_mut().pre_exec_all(input);

            // Insert input if the location is already known
            EH::qemu_pre_exec(self, input);

            // Run QEMU
            let exit_reason = self.run_qemu();

            // Handle QEMU exit
            if let Some(exit_handler_result) = EH::qemu_post_exec(self, exit_reason, input)? {
                return Ok(exit_handler_result);
            }
        }
    }

    /// This function will run the emulator until the next breakpoint, or until finish.
    /// # Safety
    ///
    /// Should, in general, be safe to call.
    /// Of course, the emulated target is not contained securely and can corrupt state or interact with the operating system.
    pub unsafe fn run_qemu(&self) -> Result<EmulatorExitResult<CM, EH, ET, S>, EmulatorExitError> {
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
                QemuExitReason::SyncExit => EmulatorExitResult::SyncExit(Rc::new(RefCell::new(
                    SyncExit::new(self.command_manager.parse(self.qemu)?),
                ))),
            }),
            Err(qemu_exit_reason_error) => Err(match qemu_exit_reason_error {
                QemuExitError::UnexpectedExit => EmulatorExitError::UnexpectedExit,
                QemuExitError::UnknownKind => EmulatorExitError::UnknownKind,
            }),
        }
    }
}

#[allow(clippy::unused_self)]
impl<CM, EH, ET, S> Emulator<CM, EH, ET, S>
where
    S: UsesInput,
{
    pub fn add_breakpoint(&self, mut bp: Breakpoint<CM, EH, ET, S>, enable: bool) -> BreakpointId {
        if enable {
            bp.enable(self.qemu);
        }

        let bp_id = bp.id();
        let bp_addr = bp.addr();

        let bp_ref = Rc::new(RefCell::new(bp));

        assert!(
            self.breakpoints_by_addr
                .borrow_mut()
                .insert(bp_addr, bp_ref.clone())
                .is_none(),
            "Adding multiple breakpoints at the same address"
        );

        assert!(
            self.breakpoints_by_id
                .borrow_mut()
                .insert(bp_id, bp_ref)
                .is_none(),
            "Adding the same breakpoint multiple times"
        );

        bp_id
    }

    pub fn remove_breakpoint(&self, bp_id: BreakpointId) {
        let bp_addr = {
            let mut bp_map = self.breakpoints_by_id.borrow_mut();
            let mut bp = bp_map
                .get_mut(&bp_id)
                .expect("Did not find the breakpoint")
                .borrow_mut();
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
