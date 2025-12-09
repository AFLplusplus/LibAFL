//! Emulator Drivers, as the name suggests, drive QEMU execution
//! They are used to perform specific actions on the emulator before and / or after QEMU runs.

#[cfg(feature = "systemmode")]
use std::collections::HashMap;
use std::{cell::OnceCell, fmt::Debug};

use libafl::{executors::ExitKind, inputs::HasTargetBytes, observers::ObserversTuple};
use libafl_bolts::os::{CTRL_C_EXIT, unix_signals::Signal};

#[cfg(not(feature = "systemmode"))]
use crate::InputLocation;
#[cfg(feature = "systemmode")]
use crate::PhysMemoryChunk;
#[cfg(feature = "systemmode")]
use crate::emu::systemmode::SystemInputLocation as InputLocation;
use crate::{
    Emulator, EmulatorExitError, EmulatorExitResult, IsSnapshotManager, Qemu, QemuError,
    QemuShutdownCause, Regs, SnapshotId, SnapshotManagerCheckError, SnapshotManagerError,
    command::{CommandError, CommandManager, IsCommand},
    modules::EmulatorModuleTuple,
};

#[cfg(not(feature = "nyx"))]
pub mod lqemu;
#[cfg(not(feature = "nyx"))]
pub use lqemu::LqemuInputSetter;

#[cfg(feature = "nyx")]
pub mod nyx;
#[cfg(feature = "nyx")]
pub use nyx::StdNyxInputSetter;

#[cfg(not(feature = "nyx"))]
pub type StdInputSetter = LqemuInputSetter;
#[cfg(feature = "nyx")]
pub type StdInputSetter = StdNyxInputSetter;

pub type StdEmulatorDriver = GenericEmulatorDriver<StdInputSetter>;

#[derive(Debug, Clone)]
pub enum EmulatorDriverResult<C> {
    /// Return to the harness immediately. Can happen at any point of the run when the handler is not supposed to handle a request.
    ReturnToClient(EmulatorExitResult<C>),

    /// The run is over and the emulator is ready for the next iteration.
    EndOfRun(ExitKind),

    /// Internal shutdown request
    ShutdownRequest,
}

#[derive(Debug, Clone)]
pub enum EmulatorDriverError {
    QemuError(QemuError),
    QemuExitReasonError(EmulatorExitError),
    SMError(SnapshotManagerError),
    SMCheckError(SnapshotManagerCheckError),
    CommandError(CommandError),
    UnhandledSignal(Signal),
    MultipleSnapshotDefinition,
    MultipleInputLocationDefinition,
    SnapshotNotFound,
    NotStartedYet,
    EndBeforeStart,
}

impl From<QemuError> for EmulatorDriverError {
    fn from(error: QemuError) -> Self {
        EmulatorDriverError::QemuError(error)
    }
}

pub trait InputSetter<I, S> {
    /// Set input in the Emulator.
    fn write_input(
        &mut self,
        qemu: Qemu,
        state: &mut S,
        input: &I,
    ) -> Result<(), EmulatorDriverError>;

    /// Set location at which input should be set.
    fn set_input_location(&mut self, location: InputLocation) -> Result<(), EmulatorDriverError>;

    /// Get the input location, if it is set.
    fn input_location(&self) -> Option<&InputLocation>;
}

#[derive(Debug, Default)]
pub struct NopInputSetter;

impl<I, S> InputSetter<I, S> for NopInputSetter {
    fn write_input(
        &mut self,
        _qemu: Qemu,
        _state: &mut S,
        _input: &I,
    ) -> Result<(), EmulatorDriverError> {
        Ok(())
    }

    fn set_input_location(&mut self, _location: InputLocation) -> Result<(), EmulatorDriverError> {
        Ok(())
    }

    fn input_location(&self) -> Option<&InputLocation> {
        None
    }
}

/// An Emulator Driver.
// TODO remove 'static when specialization will be stable
pub trait EmulatorDriver<C, CM, ET, I, S, SM>: 'static + Sized
where
    C: Clone,
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    /// Just before calling user's harness for the first time.
    /// Called only once
    fn first_harness_exec(emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>, state: &mut S) {
        emulator.modules.first_exec_all(emulator.qemu, state);
    }

    /// Just before calling user's harness
    fn pre_harness_exec(
        emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>,
        state: &mut S,
        input: &I,
    ) {
        emulator.modules.pre_exec_all(emulator.qemu, state, input);
    }

    /// Just after returning from user's harness
    fn post_harness_exec<OT>(
        emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>,
        input: &I,
        observers: &mut OT,
        state: &mut S,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
    {
        emulator
            .modules
            .post_exec_all(emulator.qemu, state, input, observers, exit_kind);
    }

    /// Just before entering QEMU
    fn pre_qemu_exec(_emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>, _input: &I) {}

    /// Just after QEMU exits
    fn post_qemu_exec(
        _emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>,
        exit_reason: &mut Result<EmulatorExitResult<C>, EmulatorExitError>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        match exit_reason {
            Ok(reason) => Ok(Some(EmulatorDriverResult::ReturnToClient(reason.clone()))),
            Err(error) => Err(error.clone().into()),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct NopEmulatorDriver;

impl<C, CM, ET, I, S, SM> EmulatorDriver<C, CM, ET, I, S, SM> for NopEmulatorDriver
where
    C: Clone,
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MapKind {
    Cov,
    Cmp,
}

pub struct StdEmulatorDriverBuilder<IS> {
    input_setter: IS,
    hooks_locked: bool,
    #[cfg(feature = "systemmode")]
    allow_page_on_start: bool,
    #[cfg(feature = "x86_64")]
    process_only: bool,
    print_commands: bool,
}

impl<IS> Default for StdEmulatorDriverBuilder<IS>
where
    IS: Default,
{
    fn default() -> Self {
        Self {
            input_setter: IS::default(),
            hooks_locked: true,
            #[cfg(feature = "systemmode")]
            allow_page_on_start: false,
            #[cfg(feature = "x86_64")]
            process_only: false,
            print_commands: false,
        }
    }
}

impl<IS> StdEmulatorDriverBuilder<IS> {
    pub fn new(
        input_setter: IS,
        hooks_locked: bool,
        #[cfg(feature = "systemmode")] allow_page_on_start: bool,
        #[cfg(feature = "x86_64")] process_only: bool,
        print_commands: bool,
    ) -> Self {
        Self {
            input_setter,
            hooks_locked,
            #[cfg(feature = "systemmode")]
            allow_page_on_start,
            #[cfg(feature = "x86_64")]
            process_only,
            print_commands,
        }
    }

    pub fn input_setter<IS2>(self, input_setter: IS2) -> StdEmulatorDriverBuilder<IS2> {
        StdEmulatorDriverBuilder::new(
            input_setter,
            self.hooks_locked,
            #[cfg(feature = "systemmode")]
            self.allow_page_on_start,
            #[cfg(feature = "x86_64")]
            self.process_only,
            self.print_commands,
        )
    }

    #[must_use]
    pub fn hooks_locked(self, hooks_locked: bool) -> Self {
        Self::new(
            self.input_setter,
            hooks_locked,
            #[cfg(feature = "systemmode")]
            self.allow_page_on_start,
            #[cfg(feature = "x86_64")]
            self.process_only,
            self.print_commands,
        )
    }

    #[cfg(feature = "systemmode")]
    pub fn allow_page_on_start(self, allow_page_on_start: bool) -> Self {
        Self::new(
            self.input_setter,
            self.hooks_locked,
            allow_page_on_start,
            #[cfg(feature = "x86_64")]
            self.process_only,
            self.print_commands,
        )
    }

    #[cfg(feature = "x86_64")]
    pub fn process_only(self, process_only: bool) -> Self {
        Self::new(
            self.input_setter,
            self.hooks_locked,
            #[cfg(feature = "systemmode")]
            self.allow_page_on_start,
            process_only,
            self.print_commands,
        )
    }

    #[must_use]
    pub fn print_commands(self, print_commands: bool) -> Self {
        Self::new(
            self.input_setter,
            self.hooks_locked,
            #[cfg(feature = "systemmode")]
            self.allow_page_on_start,
            #[cfg(feature = "x86_64")]
            self.process_only,
            print_commands,
        )
    }

    pub fn build(self) -> GenericEmulatorDriver<IS> {
        GenericEmulatorDriver {
            input_setter: self.input_setter,
            snapshot_id: OnceCell::new(),
            hooks_locked: self.hooks_locked,
            #[cfg(feature = "systemmode")]
            allow_page_on_start: self.allow_page_on_start,
            #[cfg(feature = "x86_64")]
            process_only: self.process_only,
            print_commands: self.print_commands,
            #[cfg(feature = "systemmode")]
            maps: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)] // cfg dependent
pub struct GenericEmulatorDriver<IS> {
    input_setter: IS,
    snapshot_id: OnceCell<SnapshotId>,
    hooks_locked: bool,
    #[cfg(feature = "systemmode")]
    allow_page_on_start: bool,
    #[cfg(feature = "x86_64")]
    process_only: bool,
    print_commands: bool,
    // maps declared by the VM
    #[cfg(feature = "systemmode")]
    maps: HashMap<MapKind, PhysMemoryChunk>,
}

#[cfg(not(feature = "nyx"))]
impl GenericEmulatorDriver<LqemuInputSetter> {
    #[must_use]
    pub fn builder() -> StdEmulatorDriverBuilder<LqemuInputSetter> {
        StdEmulatorDriverBuilder::<LqemuInputSetter>::default()
    }
}

#[cfg(feature = "nyx")]
impl GenericEmulatorDriver<StdNyxInputSetter> {
    #[must_use]
    pub fn builder() -> StdEmulatorDriverBuilder<StdNyxInputSetter> {
        StdEmulatorDriverBuilder::<StdNyxInputSetter>::default()
    }
}

impl<IS> GenericEmulatorDriver<IS> {
    pub fn write_input<I, S>(
        &mut self,
        qemu: Qemu,
        state: &mut S,
        input: &I,
    ) -> Result<(), EmulatorDriverError>
    where
        IS: InputSetter<I, S>,
    {
        self.input_setter.write_input(qemu, state, input)
    }

    pub fn input_setter(&self) -> &IS {
        &self.input_setter
    }

    pub fn input_setter_mut(&mut self) -> &mut IS {
        &mut self.input_setter
    }

    pub fn set_snapshot_id(&self, snapshot_id: SnapshotId) -> Result<(), SnapshotId> {
        self.snapshot_id.set(snapshot_id)
    }

    pub fn snapshot_id(&self) -> Option<SnapshotId> {
        Some(*self.snapshot_id.get()?)
    }

    // return if was locked or not
    pub fn unlock_hooks(&mut self) -> bool {
        let was_locked = self.hooks_locked;
        self.hooks_locked = false;
        was_locked
    }

    #[cfg(feature = "systemmode")]
    pub fn allow_page_on_start(&self) -> bool {
        self.allow_page_on_start
    }

    #[cfg(feature = "x86_64")]
    pub fn is_process_only(&self) -> bool {
        self.process_only
    }

    #[cfg(feature = "systemmode")]
    pub fn maps(&self) -> &HashMap<MapKind, PhysMemoryChunk> {
        &self.maps
    }

    #[cfg(feature = "systemmode")]
    pub fn maps_mut(&mut self) -> &mut HashMap<MapKind, PhysMemoryChunk> {
        &mut self.maps
    }
}

// TODO: replace handlers with generics to permit compile-time customization of handlers
impl<C, CM, ET, I, IS, S, SM> EmulatorDriver<C, CM, ET, I, S, SM> for GenericEmulatorDriver<IS>
where
    C: IsCommand<CM::Commands, CM, Self, ET, I, S, SM>,
    CM: CommandManager<C, Self, ET, I, S, SM, Commands = C>,
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    IS: InputSetter<I, S> + 'static,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn first_harness_exec(emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>, state: &mut S) {
        emulator.modules.first_exec_all(emulator.qemu, state);
    }

    fn pre_harness_exec(
        emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>,
        state: &mut S,
        input: &I,
    ) {
        emulator.modules.pre_exec_all(emulator.qemu, state, input);

        // set the input in the target, according the input setter
        // this should be run iif the emulator is "started".
        emulator
            .driver
            .input_setter
            .write_input(emulator.qemu, state, input)
            .unwrap();
    }

    fn post_harness_exec<OT>(
        emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>,
        input: &I,
        observers: &mut OT,
        state: &mut S,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<I, S>,
    {
        emulator
            .modules
            .post_exec_all(emulator.qemu, state, input, observers, exit_kind);
    }

    fn pre_qemu_exec(_emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>, _input: &I) {}

    fn post_qemu_exec(
        emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>,
        exit_reason: &mut Result<EmulatorExitResult<C>, EmulatorExitError>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emulator.qemu();

        // Check if QEMU existed because of an error or to handle some request
        let mut exit_reason = match exit_reason {
            Ok(exit_reason) => exit_reason,
            Err(exit_error) => match exit_error {
                EmulatorExitError::UnexpectedExit => {
                    if emulator.started {
                        if let Some(snapshot_id) = emulator.driver.snapshot_id.get() {
                            emulator.snapshot_manager.restore(qemu, snapshot_id)?;
                        }

                        return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Crash)));
                    }

                    Err(exit_error.clone())?
                }
                _ => Err(exit_error.clone())?,
            },
        };

        // If QEMU stopped because of a request, handle it here
        let (command, ret_reg): (Option<C>, Option<Regs>) = match &mut exit_reason {
            EmulatorExitResult::QemuExit(shutdown_cause) => match shutdown_cause {
                QemuShutdownCause::HostSignal(signal) => {
                    signal.handle();
                    return Err(EmulatorDriverError::UnhandledSignal(*signal));
                }
                QemuShutdownCause::GuestPanic => {
                    return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Crash)));
                }
                QemuShutdownCause::GuestShutdown | QemuShutdownCause::HostQmpQuit => {
                    log::warn!("Guest shutdown. Stopping fuzzing...");
                    std::process::exit(CTRL_C_EXIT);
                }
                _ => panic!("Unhandled QEMU shutdown cause: {shutdown_cause:?}."),
            },
            EmulatorExitResult::Crash => {
                return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Crash)));
            }
            EmulatorExitResult::Timeout => {
                return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Timeout)));
            }
            EmulatorExitResult::FuzzingStarts => {
                return Ok(Some(EmulatorDriverResult::ReturnToClient(
                    EmulatorExitResult::FuzzingStarts,
                )));
            }
            EmulatorExitResult::Breakpoint(bp) => (bp.trigger(qemu), None),
            EmulatorExitResult::CustomInsn(custom_insn) => {
                let command = custom_insn.command().clone();
                (Some(command), Some(custom_insn.ret_reg()))
            }
        };

        // If QEMU requested to handle a command, run it here.
        if let Some(cmd) = command {
            if emulator.driver.print_commands {
                println!("Received command: {cmd:?}");
            }
            cmd.run(emulator, ret_reg)
        } else {
            Ok(Some(EmulatorDriverResult::ReturnToClient(
                exit_reason.clone(),
            )))
        }
    }
}

impl<C> TryFrom<EmulatorDriverResult<C>> for ExitKind
where
    C: Debug,
{
    type Error = String;

    fn try_from(value: EmulatorDriverResult<C>) -> Result<Self, Self::Error> {
        match value {
            EmulatorDriverResult::ReturnToClient(unhandled_qemu_exit) => {
                Err(format!("Unhandled QEMU exit: {:?}", &unhandled_qemu_exit))
            }
            EmulatorDriverResult::EndOfRun(exit_kind) => Ok(exit_kind),
            EmulatorDriverResult::ShutdownRequest => {
                log::warn!("Shutdown request. Stopping fuzzing...");
                std::process::exit(CTRL_C_EXIT);
            }
        }
    }
}
