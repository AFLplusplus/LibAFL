//! Emulator Drivers, as the name suggests, drive QEMU execution
//! They are used to perform specific actions on the emulator before and / or after QEMU runs.

use std::{cell::OnceCell, fmt::Debug};

use libafl::{executors::ExitKind, inputs::HasTargetBytes, observers::ObserversTuple};
use libafl_bolts::os::{CTRL_C_EXIT, unix_signals::Signal};
use typed_builder::TypedBuilder;

use crate::{
    Emulator, EmulatorExitError, EmulatorExitResult, InputLocation, IsSnapshotManager, QemuError,
    QemuShutdownCause, Regs, SnapshotId, SnapshotManagerCheckError, SnapshotManagerError,
    command::{CommandError, CommandManager, InputCommand, IsCommand},
    modules::EmulatorModuleTuple,
};

#[cfg(all(
    any(cpu_target = "i386", cpu_target = "x86_64"),
    feature = "systemmode"
))]
pub mod nyx;
#[cfg(all(
    any(cpu_target = "i386", cpu_target = "x86_64"),
    feature = "systemmode"
))]
pub use nyx::{NyxEmulatorDriver, NyxEmulatorDriverBuilder};

#[derive(Debug, Clone)]
pub enum EmulatorDriverResult<C> {
    /// Return to the harness immediately. Can happen at any point of the run when the handler is not supposed to handle a request.
    ReturnToHarness(EmulatorExitResult<C>),

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
    MultipleInputDefinition,
    SnapshotNotFound,
}

impl From<QemuError> for EmulatorDriverError {
    fn from(error: QemuError) -> Self {
        EmulatorDriverError::QemuError(error)
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
        _state: &mut S,
        exit_reason: &mut Result<EmulatorExitResult<C>, EmulatorExitError>,
        _input: &I,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        match exit_reason {
            Ok(reason) => Ok(Some(EmulatorDriverResult::ReturnToHarness(reason.clone()))),
            Err(error) => Err(error.clone().into()),
        }
    }
}

pub struct NopEmulatorDriver;
impl<C, CM, ET, I, S, SM> EmulatorDriver<C, CM, ET, I, S, SM> for NopEmulatorDriver
where
    C: Clone,
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
}

#[derive(Clone, Debug, Default, TypedBuilder)]
#[allow(clippy::struct_excessive_bools)] // cfg dependent
pub struct StdEmulatorDriver {
    #[builder(default = OnceCell::new())]
    snapshot_id: OnceCell<SnapshotId>,
    #[builder(default = OnceCell::new())]
    input_location: OnceCell<InputLocation>,
    #[builder(default = true)]
    hooks_locked: bool,
    #[cfg(feature = "systemmode")]
    #[builder(default = false)]
    allow_page_on_start: bool,
    #[cfg(feature = "x86_64")]
    #[builder(default = false)]
    process_only: bool,
    #[builder(default = false)]
    print_commands: bool,
}

impl StdEmulatorDriver {
    pub fn set_input_location(&self, input_location: InputLocation) -> Result<(), InputLocation> {
        self.input_location.set(input_location)
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
}

// TODO: replace handlers with generics to permit compile-time customization of handlers
impl<C, CM, ET, I, S, SM> EmulatorDriver<C, CM, ET, I, S, SM> for StdEmulatorDriver
where
    C: IsCommand<CM::Commands, CM, Self, ET, I, S, SM>,
    CM: CommandManager<C, Self, ET, I, S, SM, Commands = C>,
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn first_harness_exec(emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>, state: &mut S) {
        if !emulator.driver.hooks_locked {
            emulator.modules.first_exec_all(emulator.qemu, state);
        }
    }

    fn pre_harness_exec(
        emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>,
        state: &mut S,
        input: &I,
    ) {
        if !emulator.driver.hooks_locked {
            emulator.modules.pre_exec_all(emulator.qemu, state, input);
        }

        let input_location = { emulator.driver.input_location.get().cloned() };

        if let Some(input_location) = input_location {
            let input_command =
                InputCommand::new(input_location.mem_chunk.clone(), input_location.cpu);

            input_command
                .run(emulator, state, input, input_location.ret_register)
                .unwrap();
        }
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
        if !emulator.driver.hooks_locked {
            emulator
                .modules
                .post_exec_all(emulator.qemu, state, input, observers, exit_kind);
        }
    }

    fn pre_qemu_exec(_emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>, _input: &I) {}

    fn post_qemu_exec(
        emulator: &mut Emulator<C, CM, Self, ET, I, S, SM>,
        state: &mut S,
        exit_reason: &mut Result<EmulatorExitResult<C>, EmulatorExitError>,
        input: &I,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emulator.qemu();

        // Check if QEMU existed because of an error or to handle some request
        let mut exit_reason = match exit_reason {
            Ok(exit_reason) => exit_reason,
            Err(exit_error) => match exit_error {
                EmulatorExitError::UnexpectedExit => {
                    if let Some(snapshot_id) = emulator.driver.snapshot_id.get() {
                        emulator.snapshot_manager.restore(qemu, snapshot_id)?;
                    }
                    return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Crash)));
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
            EmulatorExitResult::Timeout => {
                return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Timeout)));
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
            cmd.run(emulator, state, input, ret_reg)
        } else {
            Ok(Some(EmulatorDriverResult::ReturnToHarness(
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
            EmulatorDriverResult::ReturnToHarness(unhandled_qemu_exit) => {
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
