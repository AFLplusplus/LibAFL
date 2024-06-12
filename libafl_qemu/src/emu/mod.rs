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
    rc::Rc,
};

use hashbrown::HashMap;
use libafl::{
    executors::ExitKind,
    inputs::HasTargetBytes,
    state::{HasExecutions, State},
};
use libafl_bolts::os::unix_signals::Signal;
use libafl_qemu_sys::{CPUArchStatePtr, GuestUsize};
pub use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};
#[cfg(emulation_mode = "usermode")]
pub use libafl_qemu_sys::{MapInfo, MmapPerms, MmapPermsIter};
use num_traits::Num;
use typed_builder::TypedBuilder;

use crate::{
    breakpoint::Breakpoint,
    command::{CommandError, InputCommand, IsCommand},
    executor::QemuExecutorState,
    sync_exit::SyncExit,
    sys::TCGTemp,
    BackdoorHookId, BlockHookId, CmpHookId, EdgeHookId, EmulatorMemoryChunk, GuestReg, HookData,
    HookId, InstructionHookId, MemAccessInfo, Qemu, QemuExitError, QemuExitReason, QemuHelperTuple,
    QemuInitError, QemuRWError, QemuShutdownCause, QemuSnapshotCheckResult, ReadHookId, Regs,
    StdInstrumentationFilter, WriteHookId, CPU,
};

#[cfg(emulation_mode = "usermode")]
mod usermode;

#[cfg(emulation_mode = "systemmode")]
mod systemmode;
#[cfg(emulation_mode = "systemmode")]
pub use systemmode::*;

use crate::{breakpoint::BreakpointId, command::CommandManager};

type CommandRef<CM, E, QT, S> = Rc<dyn IsCommand<CM, E, QT, S>>;
type BreakpointMutRef<CM, E, QT, S> = Rc<RefCell<Breakpoint<CM, E, QT, S>>>;

#[derive(Clone, Copy)]
pub enum GuestAddrKind {
    Physical(GuestPhysAddr),
    Virtual(GuestVirtAddr),
}

#[derive(Debug, Clone)]
pub enum EmulatorExitResult<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    QemuExit(QemuShutdownCause), // QEMU ended for some reason.
    Breakpoint(Rc<RefCell<Breakpoint<CM, E, QT, S>>>), // Breakpoint triggered. Contains the address of the trigger.
    SyncExit(Rc<RefCell<SyncExit<CM, E, QT, S>>>), // Synchronous backdoor: The guest triggered a backdoor and should return to LibAFL.
}

#[derive(Debug, Clone)]
pub enum EmulatorExitError {
    UnknownKind,
    UnexpectedExit,
    CommandError(CommandError),
    BreakpointNotFound(GuestAddr),
}

#[derive(Debug, Clone)]
pub enum ExitHandlerResult<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    ReturnToHarness(EmulatorExitResult<CM, E, QT, S>), // Return to the harness immediately. Can happen at any point of the run when the handler is not supposed to handle a request.
    EndOfRun(ExitKind), // The run is over and the emulator is ready for the next iteration.
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
pub enum SnapshotManagerError {
    SnapshotIdNotFound(SnapshotId),
    MemoryInconsistencies(u64),
}

#[derive(Debug, Clone)]
pub enum SnapshotManagerCheckError {
    SnapshotManagerError(SnapshotManagerError),
    SnapshotCheckError(QemuSnapshotCheckResult),
}

impl<CM, E, QT, S> TryFrom<ExitHandlerResult<CM, E, QT, S>> for ExitKind
where
    CM: CommandManager<E, QT, S> + Debug,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S> + Debug,
    S: State + HasExecutions + Debug,
{
    type Error = String;

    fn try_from(value: ExitHandlerResult<CM, E, QT, S>) -> Result<Self, Self::Error> {
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
    fn do_check(
        &self,
        reference_snapshot_id: &SnapshotId,
        qemu: &Qemu,
    ) -> Result<QemuSnapshotCheckResult, SnapshotManagerError>;

    fn check(
        &self,
        reference_snapshot_id: &SnapshotId,
        qemu: &Qemu,
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

// TODO: Rework with generics for command handlers?
pub trait EmulatorExitHandler<QT, S>: Sized + Debug + Clone
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn qemu_pre_run<CM: CommandManager<Self, QT, S>>(
        emu: &Emulator<CM, Self, QT, S>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
    );

    fn qemu_post_run<CM: CommandManager<Self, QT, S>>(
        emu: &Emulator<CM, Self, QT, S>,
        exit_reason: Result<EmulatorExitResult<CM, Self, QT, S>, EmulatorExitError>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
    ) -> Result<Option<ExitHandlerResult<CM, Self, QT, S>>, ExitHandlerError>;
}

/// Special kind of Exit handler with no data embedded.
/// As a result, it is safe to transmute from any `Emulator` implementing `EmuExitHandler` to this one,
/// since it won't use any data which could cause type confusion.
#[derive(Clone, Debug)]
pub struct NopEmulatorExitHandler;

impl<QT, S> EmulatorExitHandler<QT, S> for NopEmulatorExitHandler
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn qemu_pre_run<CM: CommandManager<Self, QT, S>>(
        _: &Emulator<CM, Self, QT, S>,
        _: &mut QemuExecutorState<QT, S>,
        _: &S::Input,
    ) {
    }

    fn qemu_post_run<CM: CommandManager<Self, QT, S>>(
        _: &Emulator<CM, Self, QT, S>,
        exit_reason: Result<EmulatorExitResult<CM, Self, QT, S>, EmulatorExitError>,
        _: &mut QemuExecutorState<QT, S>,
        _: &S::Input,
    ) -> Result<Option<ExitHandlerResult<CM, Self, QT, S>>, ExitHandlerError> {
        match exit_reason {
            Ok(reason) => Ok(Some(ExitHandlerResult::ReturnToHarness(reason))),
            Err(error) => Err(error)?,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputLocation {
    mem_chunk: EmulatorMemoryChunk,
    cpu: CPU,
    ret_register: Option<Regs>,
}

impl InputLocation {
    #[must_use]
    pub fn new(mem_chunk: EmulatorMemoryChunk, cpu: CPU, ret_register: Option<Regs>) -> Self {
        Self {
            mem_chunk,
            cpu,
            ret_register,
        }
    }
}

/// Synchronous Exit handler maintaining only one snapshot.
#[derive(Debug, Clone, TypedBuilder)]
pub struct StdEmulatorExitHandler<SM>
where
    SM: IsSnapshotManager + Clone,
{
    snapshot_manager: RefCell<SM>,
    #[builder(default)]
    snapshot_id: OnceCell<SnapshotId>,
    #[builder(default)]
    input_location: OnceCell<InputLocation>,
}

impl<SM> StdEmulatorExitHandler<SM>
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
impl<QT, S, SM> EmulatorExitHandler<QT, S> for StdEmulatorExitHandler<SM>
where
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn qemu_pre_run<CM: CommandManager<Self, QT, S>>(
        emu: &Emulator<CM, Self, QT, S>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
    ) {
        let exit_handler = emu.exit_handler.borrow();

        if let Some(input_location) = exit_handler.input_location.get() {
            let input_command =
                InputCommand::new(input_location.mem_chunk.clone(), input_location.cpu);
            input_command
                .run(emu, qemu_executor_state, input, input_location.ret_register)
                .unwrap();
        }
    }

    fn qemu_post_run<CM: CommandManager<Self, QT, S>>(
        emu: &Emulator<CM, Self, QT, S>,
        exit_reason: Result<EmulatorExitResult<CM, Self, QT, S>, EmulatorExitError>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
    ) -> Result<Option<ExitHandlerResult<CM, Self, QT, S>>, ExitHandlerError> {
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
        let (command, ret_reg): (Option<CommandRef<CM, Self, QT, S>>, Option<Regs>) =
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
            cmd.run(emu, qemu_executor_state, input, ret_reg)
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

impl<CM, E, QT, S> Display for EmulatorExitResult<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
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

#[derive(Clone, Debug, TypedBuilder)]
pub struct Emulator<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    command_manager: CM,
    exit_handler: RefCell<E>,
    #[builder(default)]
    breakpoints_by_addr: RefCell<HashMap<GuestAddr, BreakpointMutRef<CM, E, QT, S>>>,
    #[builder(default)]
    breakpoints_by_id: RefCell<HashMap<BreakpointId, BreakpointMutRef<CM, E, QT, S>>>,
    qemu: Qemu,
    _phantom: PhantomData<(QT, S)>,
}

#[allow(clippy::unused_self)]
impl<CM, E, QT, S> Emulator<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    #[allow(clippy::must_use_candidate, clippy::similar_names)]
    pub fn new(
        args: &[String],
        env: &[(String, String)],
        exit_handler: E,
        command_manager: CM,
    ) -> Result<Self, QemuInitError> {
        let qemu = Qemu::init(args, env)?;

        Self::new_with_qemu(qemu, exit_handler, command_manager)
    }

    pub fn new_with_qemu(
        qemu: Qemu,
        exit_handler: E,
        command_manager: CM,
    ) -> Result<Self, QemuInitError> {
        Ok(Emulator {
            command_manager,
            exit_handler: RefCell::new(exit_handler),
            breakpoints_by_addr: RefCell::new(HashMap::new()),
            breakpoints_by_id: RefCell::new(HashMap::new()),
            _phantom: PhantomData,
            qemu,
        })
    }

    #[must_use]
    pub fn qemu(&self) -> &Qemu {
        &self.qemu
    }

    #[must_use]
    pub fn exit_handler(&self) -> &RefCell<E> {
        &self.exit_handler
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
    pub fn write_reg<R, T>(&self, reg: R, val: T) -> Result<(), QemuRWError>
    where
        T: Num + PartialOrd + Copy + Into<GuestReg>,
        R: Into<i32> + Clone,
    {
        self.qemu.write_reg(reg, val)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn read_reg<R, T>(&self, reg: R) -> Result<T, QemuRWError>
    where
        T: Num + PartialOrd + Copy + From<GuestReg>,
        R: Into<i32> + Clone,
    {
        self.qemu.read_reg(reg)
    }

    pub fn add_breakpoint(&self, mut bp: Breakpoint<CM, E, QT, S>, enable: bool) -> BreakpointId {
        if enable {
            bp.enable(&self.qemu);
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
            bp.disable(&self.qemu);
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
    unsafe fn run_qemu(&self) -> Result<EmulatorExitResult<CM, E, QT, S>, EmulatorExitError> {
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
        input: &S::Input,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
    ) -> Result<ExitHandlerResult<CM, E, QT, S>, ExitHandlerError> {
        loop {
            // Insert input if the location is already known
            E::qemu_pre_run(self, qemu_executor_state, input);

            // Run QEMU
            let exit_reason = self.run_qemu();

            // Handle QEMU exit
            if let Some(exit_handler_result) =
                E::qemu_post_run(self, exit_reason, qemu_executor_state, input)?
            {
                return Ok(exit_handler_result);
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
        gen: Option<unsafe extern "C" fn(T, GuestAddr, GuestAddr) -> u64>,
        exec: Option<unsafe extern "C" fn(T, u64)>,
    ) -> EdgeHookId {
        self.qemu.add_edge_hooks(data, gen, exec)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn add_block_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<unsafe extern "C" fn(T, GuestAddr) -> u64>,
        post_gen: Option<unsafe extern "C" fn(T, GuestAddr, GuestUsize)>,
        exec: Option<unsafe extern "C" fn(T, u64)>,
    ) -> BlockHookId {
        self.qemu.add_block_hooks(data, gen, post_gen, exec)
    }

    #[deprecated(
        note = "This function has been moved to the `Qemu` low-level structure. Please access it through `emu.qemu()`."
    )]
    pub fn add_read_hooks<T: Into<HookData>>(
        &self,
        data: T,
        gen: Option<unsafe extern "C" fn(T, GuestAddr, *mut TCGTemp, MemAccessInfo) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec2: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec4: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec8: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec_n: Option<unsafe extern "C" fn(T, u64, GuestAddr, usize)>,
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
        gen: Option<unsafe extern "C" fn(T, GuestAddr, *mut TCGTemp, MemAccessInfo) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec2: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec4: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec8: Option<unsafe extern "C" fn(T, u64, GuestAddr)>,
        exec_n: Option<unsafe extern "C" fn(T, u64, GuestAddr, usize)>,
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
        gen: Option<unsafe extern "C" fn(T, GuestAddr, usize) -> u64>,
        exec1: Option<unsafe extern "C" fn(T, u64, u8, u8)>,
        exec2: Option<unsafe extern "C" fn(T, u64, u16, u16)>,
        exec4: Option<unsafe extern "C" fn(T, u64, u32, u32)>,
        exec8: Option<unsafe extern "C" fn(T, u64, u64, u64)>,
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
        callback: extern "C" fn(T, CPUArchStatePtr, GuestAddr),
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
