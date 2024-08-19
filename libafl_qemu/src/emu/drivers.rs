//! Emulator Drivers, as the name suggests, drive QEMU execution
//! They are used to perform specific actions on the emulator before and / or after QEMU runs.

use std::{cell::OnceCell, fmt::Debug};

use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_bolts::os::unix_signals::Signal;

use crate::{
    command::{CommandError, CommandManager, InputCommand, IsCommand},
    Emulator, EmulatorExitError, EmulatorExitResult, InputLocation, IsSnapshotManager,
    QemuShutdownCause, Regs, SnapshotId, SnapshotManagerCheckError, SnapshotManagerError,
};

#[derive(Debug, Clone)]
pub enum EmulatorDriverResult<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    /// Return to the harness immediately. Can happen at any point of the run when the handler is not supposed to handle a request.
    ReturnToHarness(EmulatorExitResult<CM, ED, ET, S, SM>),

    /// The run is over and the emulator is ready for the next iteration.
    EndOfRun(ExitKind),
}

#[derive(Debug, Clone)]
pub enum EmulatorDriverError {
    QemuExitReasonError(EmulatorExitError),
    SMError(SnapshotManagerError),
    SMCheckError(SnapshotManagerCheckError),
    CommandError(CommandError),
    UnhandledSignal(Signal),
    MultipleSnapshotDefinition,
    MultipleInputDefinition,
    SnapshotNotFound,
}

/// An Emulator Driver.
// TODO remove 'static when specialization will be stable
pub trait EmulatorDriver<CM, ET, S, SM>: 'static + Sized
where
    CM: CommandManager<Self, ET, S, SM>,
    S: UsesInput,
{
    fn pre_exec(&mut self, _emulator: &mut Emulator<CM, Self, ET, S, SM>, _input: &S::Input) {}

    #[allow(clippy::type_complexity)]
    fn post_exec(
        &mut self,
        _emulator: &mut Emulator<CM, Self, ET, S, SM>,
        exit_reason: &mut Result<EmulatorExitResult<CM, Self, ET, S, SM>, EmulatorExitError>,
        _input: &S::Input,
    ) -> Result<Option<EmulatorDriverResult<CM, Self, ET, S, SM>>, EmulatorDriverError> {
        match exit_reason {
            Ok(reason) => Ok(Some(EmulatorDriverResult::ReturnToHarness(reason.clone()))),
            Err(error) => Err(error.clone().into()),
        }
    }
}

pub struct NopEmulatorDriver;
impl<CM, ET, S, SM> EmulatorDriver<CM, ET, S, SM> for NopEmulatorDriver
where
    CM: CommandManager<Self, ET, S, SM>,
    S: UsesInput,
{
}

#[derive(Clone, Debug)]
pub struct StdEmulatorDriver {
    snapshot_id: OnceCell<SnapshotId>,
    input_location: OnceCell<InputLocation>,
}

impl Default for StdEmulatorDriver {
    fn default() -> Self {
        StdEmulatorDriver::new()
    }
}

impl StdEmulatorDriver {
    #[must_use]
    pub fn new() -> Self {
        Self {
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
}

// TODO: replace handlers with generics to permit compile-time customization of handlers
impl<CM, ET, S, SM> EmulatorDriver<CM, ET, S, SM> for StdEmulatorDriver
where
    CM: CommandManager<StdEmulatorDriver, ET, S, SM>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn pre_exec(&mut self, emulator: &mut Emulator<CM, Self, ET, S, SM>, input: &S::Input) {
        let input_location = { self.input_location.get().cloned() };

        if let Some(input_location) = input_location {
            let input_command =
                InputCommand::new(input_location.mem_chunk.clone(), input_location.cpu);

            input_command
                .run(emulator, self, input, input_location.ret_register)
                .unwrap();
        }
    }

    fn post_exec(
        &mut self,
        emulator: &mut Emulator<CM, Self, ET, S, SM>,
        exit_reason: &mut Result<EmulatorExitResult<CM, Self, ET, S, SM>, EmulatorExitError>,
        input: &S::Input,
    ) -> Result<Option<EmulatorDriverResult<CM, Self, ET, S, SM>>, EmulatorDriverError> {
        let qemu = emulator.qemu();

        let mut exit_reason = match exit_reason {
            Ok(exit_reason) => exit_reason,
            Err(exit_error) => match exit_error {
                EmulatorExitError::UnexpectedExit => {
                    if let Some(snapshot_id) = self.snapshot_id.get() {
                        emulator.snapshot_manager.restore(qemu, snapshot_id)?;
                    }
                    return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Crash)));
                }
                _ => Err(exit_error.clone())?,
            },
        };

        #[allow(clippy::type_complexity)]
        let (command, ret_reg): (Option<CM::Commands>, Option<Regs>) = match &mut exit_reason {
            EmulatorExitResult::QemuExit(shutdown_cause) => match shutdown_cause {
                QemuShutdownCause::HostSignal(signal) => {
                    signal.handle();
                    return Err(EmulatorDriverError::UnhandledSignal(*signal));
                }
                QemuShutdownCause::GuestPanic => {
                    return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Crash)))
                }
                _ => panic!("Unhandled QEMU shutdown cause: {shutdown_cause:?}."),
            },
            EmulatorExitResult::Breakpoint(bp) => (bp.trigger(qemu), None),
            EmulatorExitResult::SyncExit(sync_backdoor) => {
                let command = sync_backdoor.command().clone();
                (Some(command), Some(sync_backdoor.ret_reg()))
            }
        };

        if let Some(cmd) = command {
            cmd.run(emulator, self, input, ret_reg)
        } else {
            Ok(Some(EmulatorDriverResult::ReturnToHarness(
                exit_reason.clone(),
            )))
        }
    }
}

impl<CM, ED, ET, S, SM> TryFrom<EmulatorDriverResult<CM, ED, ET, S, SM>> for ExitKind
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    type Error = String;

    fn try_from(value: EmulatorDriverResult<CM, ED, ET, S, SM>) -> Result<Self, Self::Error> {
        match value {
            EmulatorDriverResult::ReturnToHarness(unhandled_qemu_exit) => {
                Err(format!("Unhandled QEMU exit: {:?}", &unhandled_qemu_exit))
            }
            EmulatorDriverResult::EndOfRun(exit_kind) => Ok(exit_kind),
        }
    }
}
