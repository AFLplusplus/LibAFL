use std::{
    fmt,
    fmt::{Debug, Display, Formatter},
    marker::PhantomData,
    ops::Range,
};

use enum_map::{Enum, EnumMap};
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_bolts::AsSlice;
use libafl_qemu_sys::GuestAddr;
#[cfg(feature = "systemmode")]
use libafl_qemu_sys::GuestPhysAddr;
use libc::c_uint;
use num_enum::TryFromPrimitive;
use paste::paste;

use crate::{
    command::parser::{
        EndCommandParser, InputPhysCommandParser, InputVirtCommandParser, LoadCommandParser,
        LqprintfCommandParser, NativeCommandParser, SaveCommandParser, StartPhysCommandParser,
        StartVirtCommandParser, TestCommandParser, VaddrFilterAllowRangeCommandParser,
        VersionCommandParser,
    },
    get_exit_arch_regs,
    modules::EmulatorModuleTuple,
    sync_exit::ExitArgs,
    Emulator, EmulatorDriverError, EmulatorDriverResult, GuestReg, InputLocation,
    IsSnapshotManager, Qemu, QemuMemoryChunk, QemuRWError, Regs, StdEmulatorDriver, CPU,
};

pub mod parser;

mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(unused_mut)]
    #![allow(unused)]
    #![allow(unused_variables)]
    #![allow(clippy::all)]
    #![allow(clippy::pedantic)]

    include!(concat!(env!("OUT_DIR"), "/libafl_qemu_bindings.rs"));
}

pub const VERSION: u64 = bindings::LIBAFL_QEMU_HDR_VERSION_NUMBER as u64;

macro_rules! define_std_command_manager {
    ($name:ident, [$($command:ty),+], [$($native_command_parser:ty),+]) => {
        paste! {
            pub struct $name<S> {
                has_started: bool,
                phantom: PhantomData<S>,
            }

            impl<S> Clone for $name<S> {
                fn clone(&self) -> Self {
                    Self {
                        has_started: self.has_started,
                        phantom: PhantomData,
                    }
                }
            }

            impl<S> Debug for $name<S> {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    write!(f, "{} (has started? {:?})", stringify!($name), self.has_started)
                }
            }

            impl<S> Default for $name<S> {
                fn default() -> Self {
                    Self {
                        has_started: false,
                        phantom: PhantomData,
                    }
                }
            }

            impl<S> $name<S> {
                fn start(&mut self) -> bool {
                    let tmp = self.has_started;
                    self.has_started = true;
                    tmp
                }

                fn has_started(&self) -> bool {
                    self.has_started
                }
            }

            impl<ET, S, SM> CommandManager<StdEmulatorDriver, ET, S, SM> for $name<S>
            where
                ET: EmulatorModuleTuple<S>,
                S: UsesInput + Unpin,
                S::Input: HasTargetBytes,
                SM: IsSnapshotManager,
            {
                type Commands = [<$name Commands>];

                #[deny(unreachable_patterns)]
                fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError> {
                    let arch_regs_map: &'static EnumMap<ExitArgs, Regs> = get_exit_arch_regs();
                    let cmd_id = qemu.read_reg(arch_regs_map[ExitArgs::Cmd])? as c_uint;

                    match cmd_id {
                        // <StartPhysCommandParser as NativeCommandParser<S>>::COMMAND_ID => Ok(StdCommandManagerCommands::StartPhysCommandParserCmd(<StartPhysCommandParser as NativeCommandParser<S>>::parse(qemu, arch_regs_map)?)),
                        $(<$native_command_parser as NativeCommandParser<Self, StdEmulatorDriver, ET, S, SM>>::COMMAND_ID => Ok(<$native_command_parser as NativeCommandParser<Self, StdEmulatorDriver, ET, S, SM>>::parse(qemu, arch_regs_map)?.into())),+,
                        _ => Err(CommandError::UnknownCommand(cmd_id.into())),
                    }
                }
            }

            #[derive(Clone, Debug)]
            pub enum [<$name Commands>]
            {
                // StartPhysCommand(StartPhysCommand)
                $($command($command)),+,
            }

            impl<ET, S, SM> IsCommand<$name<S>, StdEmulatorDriver, ET, S, SM> for [<$name Commands>]
            where
                ET: EmulatorModuleTuple<S>,
                S: UsesInput + Unpin,
                S::Input: HasTargetBytes,
                SM: IsSnapshotManager,
            {
                fn usable_at_runtime(&self) -> bool {
                    match self {
                        $([<$name Commands>]::$command(cmd) => <$command as IsCommand<$name<S>, StdEmulatorDriver, ET, S, SM>>::usable_at_runtime(cmd)),+
                    }
                }

                fn run(&self,
                    emu: &mut Emulator<$name<S>, StdEmulatorDriver, ET, S, SM>,
                    state: &mut S,
                    input: &S::Input,
                    ret_reg: Option<Regs>
                ) -> Result<Option<EmulatorDriverResult<$name<S>, StdEmulatorDriver, ET, S, SM>>, EmulatorDriverError> {
                    match self {
                        $([<$name Commands>]::$command(cmd) => cmd.run(emu, state, input, ret_reg)),+
                    }
                }
            }

            $(
                impl From<$command> for [<$name Commands>] {
                    fn from(cmd: $command) -> [<$name Commands>] {
                        [<$name Commands>]::$command(cmd)
                    }
                }
            )+
        }
    };
}

pub trait CommandManager<ED, ET, S, SM>: Sized + Debug
where
    S: UsesInput,
{
    type Commands: IsCommand<Self, ED, ET, S, SM>;

    fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError>;
}

#[derive(Clone, Debug)]
pub struct NopCommandManager;
impl<ED, ET, S, SM> CommandManager<ED, ET, S, SM> for NopCommandManager
where
    S: UsesInput,
{
    type Commands = NopCommand;

    fn parse(&self, _qemu: Qemu) -> Result<Self::Commands, CommandError> {
        Ok(NopCommand)
    }
}

define_std_command_manager!(
    StdCommandManager,
    [
        StartCommand,
        InputCommand,
        SaveCommand,
        LoadCommand,
        EndCommand,
        VersionCommand,
        AddressAllowCommand,
        LqprintfCommand,
        TestCommand
    ],
    [
        StartPhysCommandParser,
        StartVirtCommandParser,
        InputPhysCommandParser,
        InputVirtCommandParser,
        SaveCommandParser,
        LoadCommandParser,
        EndCommandParser,
        VersionCommandParser,
        VaddrFilterAllowRangeCommandParser,
        LqprintfCommandParser,
        TestCommandParser
    ]
);

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_UNKNOWN.0 as u64, // Should not be used
    Ok = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_OK.0 as u64,           // Normal exit
    Crash = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_CRASH.0 as u64, // Crash reported in the VM
}

pub trait IsCommand<CM, ED, ET, S, SM>: Clone + Debug
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    /// Used to know whether the command can be run during a backdoor, or if it is necessary to go out of
    /// the QEMU VM to run the command.
    fn usable_at_runtime(&self) -> bool;

    /// Command handler.
    ///     - `input`: The input for the current emulator run.
    ///     - `ret_reg`: The register in which the guest return value should be written, if any.
    /// Returns
    ///     - `InnerHandlerResult`: How the high-level handler should behave
    #[allow(clippy::type_complexity)]
    fn run(
        &self,
        emu: &mut Emulator<CM, ED, ET, S, SM>,
        state: &mut S,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError>;
}

#[derive(Debug, Clone)]
pub enum CommandError {
    UnknownCommand(GuestReg),
    RWError(QemuRWError),
    VersionDifference(u64),
    TestDifference(GuestReg, GuestReg), // received, expected
    StartedTwice,
    EndBeforeStart,
}

impl From<QemuRWError> for CommandError {
    fn from(error: QemuRWError) -> Self {
        CommandError::RWError(error)
    }
}

#[derive(Debug, Clone)]
pub struct NopCommand;

impl Display for NopCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "NopCommand")
    }
}

impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for NopCommand
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct SaveCommand;
impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorDriver, ET, S, SM> for SaveCommand
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<StdEmulatorDriver, ET, S, SM>,
    S: UsesInput + Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorDriver, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, StdEmulatorDriver, ET, S, SM>>, EmulatorDriverError>
    {
        let qemu = emu.qemu();
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        emu.driver_mut()
            .set_snapshot_id(snapshot_id)
            .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand;

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorDriver, ET, S, SM> for LoadCommand
where
    CM: CommandManager<StdEmulatorDriver, ET, S, SM>,
    S: UsesInput,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorDriver, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, StdEmulatorDriver, ET, S, SM>>, EmulatorDriverError>
    {
        let qemu = emu.qemu();

        let snapshot_id = emu
            .driver_mut()
            .snapshot_id()
            .ok_or(EmulatorDriverError::SnapshotNotFound)?;

        emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;

        #[cfg(feature = "paranoid_debug")]
        emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct InputCommand {
    location: QemuMemoryChunk,
    cpu: CPU,
}

impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for InputCommand
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        let ret_value = self
            .location
            .write(qemu, input.target_bytes().as_slice())
            .unwrap();

        if let Some(reg) = ret_reg {
            self.cpu.write_reg(reg, ret_value).unwrap();
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct StartCommand {
    input_location: QemuMemoryChunk,
}
impl<ET, S, SM> IsCommand<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM> for StartCommand
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM>,
        state: &mut S,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<
        Option<EmulatorDriverResult<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM>>,
        EmulatorDriverError,
    > {
        if emu.command_manager_mut().start() {
            return Err(EmulatorDriverError::CommandError(
                CommandError::StartedTwice,
            ));
        }

        let qemu = emu.qemu();

        // Snapshot VM
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        // Set snapshot ID to restore to after fuzzing ends
        emu.driver_mut()
            .set_snapshot_id(snapshot_id)
            .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

        // Save input location for next runs
        emu.driver_mut()
            .set_input_location(InputLocation::new(
                self.input_location.clone(),
                qemu.current_cpu().unwrap(),
                ret_reg,
            ))
            .unwrap();

        // Write input to input location
        let ret_value = self
            .input_location
            .write(qemu, input.target_bytes().as_slice())
            .unwrap();

        // Unleash hooks if locked
        if emu.driver_mut().unlock_hooks() {
            // Prepare hooks
            emu.modules_mut().first_exec_all(state);
            emu.modules_mut().pre_exec_all(state, input);
        }

        // Auto page filtering if option is enabled
        #[cfg(feature = "systemmode")]
        if emu.driver_mut().allow_page_on_start() {
            if let Some(page_id) = qemu.current_cpu().unwrap().current_paging_id() {
                emu.modules_mut().modules_mut().allow_page_id_all(page_id);
            }
        }

        #[cfg(feature = "x86_64")]
        if emu.driver_mut().is_process_only() {
            emu.modules_mut()
                .modules_mut()
                .allow_address_range_all(crate::PROCESS_ADDRESS_RANGE);
        }

        // Make sure JIT cache is empty just before starting
        qemu.flush_jit();

        // Set input size in return register if there is any
        if let Some(reg) = ret_reg {
            qemu.write_reg(reg, ret_value).unwrap();
        }

        log::info!("Fuzzing starts");

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct EndCommand {
    exit_kind: Option<ExitKind>,
}

impl<ET, S, SM> IsCommand<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM> for EndCommand
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<
        Option<EmulatorDriverResult<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM>>,
        EmulatorDriverError,
    > {
        let qemu = emu.qemu();

        if !emu.command_manager_mut().has_started() {
            return Err(EmulatorDriverError::CommandError(
                CommandError::EndBeforeStart,
            ));
        }

        let snapshot_id = emu
            .driver_mut()
            .snapshot_id()
            .ok_or(EmulatorDriverError::SnapshotNotFound)?;

        emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;

        #[cfg(feature = "paranoid_debug")]
        emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

        Ok(Some(EmulatorDriverResult::EndOfRun(
            self.exit_kind.unwrap(),
        )))
    }
}

#[derive(Debug, Clone)]
pub struct VersionCommand(u64);

impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for VersionCommand
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        let guest_version = self.0;

        if VERSION == guest_version {
            Ok(None)
        } else {
            Err(EmulatorDriverError::CommandError(
                CommandError::VersionDifference(guest_version),
            ))
        }
    }
}

#[cfg(feature = "systemmode")]
#[derive(Debug, Clone)]
pub struct PageAllowCommand {
    page_id: GuestPhysAddr,
}

#[cfg(feature = "systemmode")]
impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for PageAllowCommand
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        emu.modules_mut()
            .modules_mut()
            .allow_page_id_all(self.page_id.clone());
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct AddressAllowCommand {
    address_range: Range<GuestAddr>,
}
impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for AddressAllowCommand
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        emu.modules_mut()
            .modules_mut()
            .allow_address_range_all(self.address_range.clone());
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LqprintfCommand {
    content: String,
}
impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for LqprintfCommand
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        print!("LQPRINTF: {}", self.content);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct TestCommand {
    expected_value: GuestReg,
    received_value: GuestReg,
}
impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for TestCommand
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        if self.expected_value == self.received_value {
            Ok(None)
        } else {
            Err(EmulatorDriverError::CommandError(
                CommandError::TestDifference(self.received_value, self.expected_value),
            ))
        }
    }
}

impl TestCommand {
    #[must_use]
    pub fn new(received_value: GuestReg, expected_value: GuestReg) -> Self {
        Self {
            expected_value,
            received_value,
        }
    }
}

impl LqprintfCommand {
    #[must_use]
    pub fn new(content: String) -> Self {
        Self { content }
    }
}

impl VersionCommand {
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self(version)
    }
}

impl AddressAllowCommand {
    #[must_use]
    pub fn new(address_range: Range<GuestAddr>) -> Self {
        Self { address_range }
    }
}

impl Display for SaveCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Save VM")
    }
}

impl Display for LoadCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reload VM")
    }
}

impl Display for InputCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Set fuzzing input @{}", self.location.addr())
    }
}

impl Display for StartCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start fuzzing with input @{}",
            self.input_location.addr()
        )
    }
}

impl Display for EndCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Exit of kind {:?}", self.exit_kind)
    }
}

impl Display for VersionCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client version: {}", self.0)
    }
}

impl Display for AddressAllowCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Addr range allow: {:?}", self.address_range)
    }
}

#[cfg(feature = "systemmode")]
impl Display for PageAllowCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Allowed page: {:?}", self.page_id)
    }
}

impl StartCommand {
    #[must_use]
    pub fn new(input_location: QemuMemoryChunk) -> Self {
        Self { input_location }
    }
}

impl EndCommand {
    #[must_use]
    pub fn new(exit_kind: Option<ExitKind>) -> Self {
        Self { exit_kind }
    }
}

impl InputCommand {
    #[must_use]
    pub fn new(location: QemuMemoryChunk, cpu: CPU) -> Self {
        Self { location, cpu }
    }
}
