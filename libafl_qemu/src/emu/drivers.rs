//! Emulator Drivers, as the name suggests, drive QEMU execution
//! They are used to perform specific actions on the emulator before and / or after QEMU runs.

use std::{cell::OnceCell, fmt::Debug};

use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
    observers::ObserversTuple,
};
use libafl_bolts::os::{unix_signals::Signal, CTRL_C_EXIT};
use typed_builder::TypedBuilder;

use crate::{
    command::{CommandError, CommandManager, InputCommand, IsCommand},
    modules::EmulatorModuleTuple,
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
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
    /// Just before calling user's harness for the first time.
    /// Called only once
    fn first_harness_exec(emulator: &mut Emulator<CM, Self, ET, S, SM>, state: &mut S) {
        emulator.modules.first_exec_all(state);
    }

    /// Just before calling user's harness
    fn pre_harness_exec(
        emulator: &mut Emulator<CM, Self, ET, S, SM>,
        state: &mut S,
        input: &S::Input,
    ) {
        emulator.modules.pre_exec_all(state, input);
    }

    /// Just after returning from user's harness
    fn post_harness_exec<OT>(
        emulator: &mut Emulator<CM, Self, ET, S, SM>,
        input: &S::Input,
        observers: &mut OT,
        state: &mut S,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
    {
        emulator
            .modules
            .post_exec_all(state, input, observers, exit_kind);
    }

    /// Just before entering QEMU
    fn pre_qemu_exec(_emulator: &mut Emulator<CM, Self, ET, S, SM>, _input: &S::Input) {}

    /// Just after QEMU exits
    #[allow(clippy::type_complexity)]
    fn post_qemu_exec(
        _emulator: &mut Emulator<CM, Self, ET, S, SM>,
        _state: &mut S,
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
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
{
}

#[derive(Clone, Debug, Default, TypedBuilder)]
#[allow(clippy::struct_excessive_bools)]
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
impl<CM, ET, S, SM> EmulatorDriver<CM, ET, S, SM> for StdEmulatorDriver
where
    CM: CommandManager<StdEmulatorDriver, ET, S, SM>,
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn first_harness_exec(emulator: &mut Emulator<CM, Self, ET, S, SM>, state: &mut S) {
        if !emulator.driver.hooks_locked {
            emulator.modules.first_exec_all(state);
        }
    }

    fn pre_harness_exec(
        emulator: &mut Emulator<CM, Self, ET, S, SM>,
        state: &mut S,
        input: &S::Input,
    ) {
        if !emulator.driver.hooks_locked {
            emulator.modules.pre_exec_all(state, input);
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
        emulator: &mut Emulator<CM, Self, ET, S, SM>,
        input: &S::Input,
        observers: &mut OT,
        state: &mut S,
        exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
    {
        if !emulator.driver.hooks_locked {
            emulator
                .modules
                .post_exec_all(state, input, observers, exit_kind);
        }
    }

    fn pre_qemu_exec(_emulator: &mut Emulator<CM, Self, ET, S, SM>, _input: &S::Input) {}

    fn post_qemu_exec(
        emulator: &mut Emulator<CM, Self, ET, S, SM>,
        state: &mut S,
        exit_reason: &mut Result<EmulatorExitResult<CM, Self, ET, S, SM>, EmulatorExitError>,
        input: &S::Input,
    ) -> Result<Option<EmulatorDriverResult<CM, Self, ET, S, SM>>, EmulatorDriverError> {
        let qemu = emulator.qemu();

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
                QemuShutdownCause::GuestShutdown | QemuShutdownCause::HostQmpQuit => {
                    log::warn!("Guest shutdown. Stopping fuzzing...");
                    std::process::exit(CTRL_C_EXIT);
                }
                _ => panic!("Unhandled QEMU shutdown cause: {shutdown_cause:?}."),
            },
            EmulatorExitResult::Timeout => {
                return Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Timeout)))
            }
            EmulatorExitResult::Breakpoint(bp) => (bp.trigger(qemu), None),
            EmulatorExitResult::SyncExit(sync_backdoor) => {
                let command = sync_backdoor.command().clone();
                (Some(command), Some(sync_backdoor.ret_reg()))
            }
        };

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
