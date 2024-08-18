//! Emulator Drivers, as the name suggests, drive QEMU execution
//! They are used to perform specific actions on the emulator before and / or after QEMU runs.

use std::cell::OnceCell;

use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_bolts::{os::unix_signals::Signal, tuples::MatchFirstType};

use crate::{
    command::{CommandError, CommandManager, InputCommand, IsCommand},
    modules::StdInstrumentationFilter,
    Emulator, EmulatorExitError, EmulatorExitResult, InputLocation, IsSnapshotManager,
    QemuShutdownCause, Regs, SnapshotId, SnapshotManagerCheckError, SnapshotManagerError,
};

#[derive(Debug, Clone)]
pub enum EmulatorDriverResult<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    /// Return to the harness immediately. Can happen at any point of the run when the handler is not supposed to handle a request.
    ReturnToHarness(EmulatorExitResult<CM, S>),

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
pub trait EmulatorDriver<CM, S, SM>: 'static
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn pre_exec<EDT, ET>(&mut self, _emulator: &mut Emulator<CM, EDT, ET, S, SM>, _input: &S::Input)
    where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
    }

    fn post_exec<EDT, ET>(
        &mut self,
        _emulator: &mut Emulator<CM, EDT, ET, S, SM>,
        _exit_reason: &mut Result<EmulatorExitResult<CM, S>, EmulatorExitError>,
        _input: &S::Input,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
        Ok(None)
    }
}

pub trait EmulatorDriverTuple<CM, S, SM>: MatchFirstType
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn pre_exec_all<EDT, ET>(
        &mut self,
        emulator: &mut Emulator<CM, EDT, ET, S, SM>,
        input: &S::Input,
    ) where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>;

    fn post_exec_all<EDT, ET>(
        &mut self,
        emulator: &mut Emulator<CM, EDT, ET, S, SM>,
        exit_reason: &mut Result<EmulatorExitResult<CM, S>, EmulatorExitError>,
        input: &S::Input,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>;
}
pub struct StdEmulatorDriver {
    snapshot_id: OnceCell<SnapshotId>,
    input_location: OnceCell<InputLocation>,
}

impl<CM, S, SM> EmulatorDriverTuple<CM, S, SM> for ()
where
    CM: CommandManager<S> + Clone,
    S: UsesInput + Clone,
{
    fn pre_exec_all<EDT, ET>(
        &mut self,
        _emulator: &mut Emulator<CM, EDT, ET, S, SM>,
        _input: &S::Input,
    ) where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
    }

    fn post_exec_all<EDT, ET>(
        &mut self,
        _emulator: &mut Emulator<CM, EDT, ET, S, SM>,
        _exit_reason: &mut Result<EmulatorExitResult<CM, S>, EmulatorExitError>,
        _input: &S::Input,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
        Ok(None)
    }
}

impl<Head, Tail, CM, S, SM> EmulatorDriverTuple<CM, S, SM> for (Head, Tail)
where
    Head: EmulatorDriver<CM, S, SM>,
    Tail: EmulatorDriverTuple<CM, S, SM>,
    CM: CommandManager<S>,
    S: UsesInput,
{
    fn pre_exec_all<EDT, ET>(
        &mut self,
        emulator: &mut Emulator<CM, EDT, ET, S, SM>,
        input: &S::Input,
    ) where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
        self.0.pre_exec(emulator, input);
        self.1.pre_exec_all(emulator, input)
    }

    fn post_exec_all<EDT, ET>(
        &mut self,
        emulator: &mut Emulator<CM, EDT, ET, S, SM>,
        exit_reason: &mut Result<EmulatorExitResult<CM, S>, EmulatorExitError>,
        input: &S::Input,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
        if let Some(driver_result) = self.0.post_exec(emulator, exit_reason, input)? {
            match driver_result {
                EmulatorDriverResult::ReturnToHarness(exit_result) => {
                    self.1.post_exec_all(emulator, exit_reason, input)?;
                    return Ok(Some(EmulatorDriverResult::ReturnToHarness(exit_result)));
                }
                _ => {}
            }
        }

        self.1.post_exec_all(emulator, exit_reason, input)
    }
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
impl<CM, S, SM> EmulatorDriver<CM, S, SM> for StdEmulatorDriver
where
    CM: CommandManager<S> + Clone,
    S: UsesInput + Clone + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn pre_exec<EDT, ET>(&mut self, emulator: &mut Emulator<CM, EDT, ET, S, SM>, input: &S::Input)
    where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
        let input_location = { self.input_location.get().cloned() };

        if let Some(input_location) = input_location {
            let input_command =
                InputCommand::new(input_location.mem_chunk.clone(), input_location.cpu);

            input_command
                .run(emulator, input, input_location.ret_register)
                .unwrap();
        }
    }

    fn post_exec<EDT, ET>(
        &mut self,
        emulator: &mut Emulator<CM, EDT, ET, S, SM>,
        exit_reason: &mut Result<EmulatorExitResult<CM, S>, EmulatorExitError>,
        input: &S::Input,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
    {
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
            cmd.run(emulator, input, ret_reg)
        } else {
            Ok(Some(EmulatorDriverResult::ReturnToHarness(
                exit_reason.clone(),
            )))
        }
    }
}
