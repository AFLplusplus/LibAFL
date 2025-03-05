use std::{cell::OnceCell, cmp::min, ptr, slice::from_raw_parts};

use libafl::{executors::ExitKind, inputs::HasTargetBytes, observers::ObserversTuple};
use libafl_bolts::os::CTRL_C_EXIT;
use typed_builder::TypedBuilder;

use crate::{
    Emulator, EmulatorDriver, EmulatorDriverError, EmulatorDriverResult, EmulatorExitError,
    EmulatorExitResult, InputLocation, IsSnapshotManager, Qemu, QemuError, QemuShutdownCause, Regs,
    SnapshotId,
    command::{CommandManager, IsCommand, nyx::bindings},
    modules::EmulatorModuleTuple,
};

#[derive(Clone, Debug, TypedBuilder)]
#[allow(clippy::struct_excessive_bools)] // cfg dependent
pub struct NyxEmulatorDriver {
    #[builder(default = OnceCell::new())]
    snapshot_id: OnceCell<SnapshotId>,
    #[builder(default = OnceCell::new())]
    input_struct_location: OnceCell<InputLocation>,
    #[builder(default = OnceCell::new())]
    input_location: OnceCell<InputLocation>,
    #[builder(default = true)]
    hooks_locked: bool,
    #[cfg(feature = "systemmode")]
    #[builder(default = false)]
    allow_page_on_start: bool, // when fuzzing starts, all modules will only accept the current page table
    #[builder(default = false)]
    print_commands: bool,
    #[builder(default = (1024 * 1024))]
    max_input_size: usize,
}

impl NyxEmulatorDriver {
    pub fn max_input_size(&self) -> usize {
        self.max_input_size
    }

    pub fn write_input<I>(&self, qemu: Qemu, input: &I) -> Result<(), QemuError>
    where
        I: HasTargetBytes,
    {
        let input_len =
            i32::try_from(min(self.max_input_size, input.target_bytes().len())).unwrap();

        let kafl_payload = bindings::kAFL_payload {
            size: input_len,
            ..Default::default()
        };

        let kafl_payload_buf = unsafe {
            from_raw_parts(
                ptr::from_ref(&kafl_payload) as *const u8,
                size_of::<bindings::kAFL_payload>(),
            )
        };

        let input_struct_mem_chunk = &self.input_struct_location.get().unwrap().mem_chunk;

        // TODO: manage endianness correctly.
        input_struct_mem_chunk.write(qemu, kafl_payload_buf)?;

        // write struct first
        self.input_location
            .get()
            .unwrap()
            .mem_chunk
            .write(qemu, input.target_bytes().as_ref())?;

        Ok(())
    }

    pub fn set_input_location(&self, input_location: InputLocation) -> Result<(), InputLocation> {
        self.input_location.set(input_location)
    }

    pub fn set_input_struct_location(
        &self,
        input_struct_location: InputLocation,
    ) -> Result<(), InputLocation> {
        self.input_struct_location.set(input_struct_location)
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
}

impl<C, CM, ET, I, S, SM> EmulatorDriver<C, CM, ET, I, S, SM> for NyxEmulatorDriver
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

        if emulator.driver.input_location.get().is_some() {
            let qemu = emulator.qemu();

            emulator.driver.write_input(qemu, input).unwrap();
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
            EmulatorExitResult::CustomInsn(sync_backdoor) => {
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
