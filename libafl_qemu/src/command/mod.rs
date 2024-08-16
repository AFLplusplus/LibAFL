use std::{
    fmt::{Debug, Display, Formatter},
    marker::PhantomData,
};

use enum_map::{Enum, EnumMap};
#[cfg(emulation_mode = "systemmode")]
use hashbrown::HashSet;
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_bolts::AsSlice;
use libc::c_uint;
use num_enum::TryFromPrimitive;
use paste::paste;

#[cfg(emulation_mode = "systemmode")]
use crate::modules::QemuInstrumentationPagingFilter;
use crate::{
    command::parser::{
        EndCommandParser, InputPhysCommandParser, InputVirtCommandParser, LoadCommandParser,
        NativeCommandParser, SaveCommandParser, StartPhysCommandParser, StartVirtCommandParser,
        VaddrFilterAllowRangeCommandParser, VersionCommandParser,
    },
    get_exit_arch_regs,
    modules::{
        HasInstrumentationFilter, QemuInstrumentationAddressRangeFilter, StdInstrumentationFilter,
    },
    sync_exit::ExitArgs,
    Emulator, EmulatorDriverError, EmulatorDriverResult, EmulatorDriverTuple, GuestReg,
    InputLocation, IsSnapshotManager, Qemu, QemuMemoryChunk, QemuRWError, Regs, StdEmulatorDriver,
    CPU,
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
    ($name:ident, [$($native_command_parser:ident),+]) => {
        paste! {
            #[derive(Clone)]
            pub struct $name<S> {
                phantom: PhantomData<S>,
            }

            impl<S> Default for $name<S> {
                fn default() -> Self {
                    StdCommandManager {
                        phantom: PhantomData
                    }
                }
            }

            impl<S> CommandManager<S> for $name<S>
            where
                S: UsesInput + Clone + Debug,
                S::Input: HasTargetBytes,
            {
                type Commands = [<$name Commands>]<S>;

                fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError> {
                    let arch_regs_map: &'static EnumMap<ExitArgs, Regs> = get_exit_arch_regs();
                    let cmd_id = qemu.read_reg::<Regs, GuestReg>(arch_regs_map[ExitArgs::Cmd])? as c_uint;

                    match cmd_id {
                        // <StartPhysCommandParser as NativeCommandParser<S>>::COMMAND_ID => Ok(StdCommandManagerCommands::StartPhysCommandParserCmd(<StartPhysCommandParser as NativeCommandParser<S>>::parse(qemu, arch_regs_map)?)),
                        $(<$native_command_parser as NativeCommandParser<S>>::COMMAND_ID => Ok([<$name Commands>]::$native_command_parser(<$native_command_parser as NativeCommandParser<S>>::parse(qemu, arch_regs_map)?))),+,
                        _ => Err(CommandError::UnknownCommand(cmd_id as GuestReg)),
                    }
                }
            }

            #[derive(Clone, Debug)]
            pub enum [<$name Commands>]<S>
            where
                S: UsesInput,
                S::Input: HasTargetBytes,
            {
                // StartPhysCommandParserCmd(<StartPhysCommandParser as NativeCommandParser<S>>::OutputCommand)
                $($native_command_parser(<$native_command_parser as NativeCommandParser<S>>::OutputCommand)),+
            }

            impl<S> IsCommand<S> for [<$name Commands>]<S>
            where
                S: UsesInput + Debug,
                S::Input: HasTargetBytes,
            {
                fn usable_at_runtime(&self) -> bool {
                    match self {
                        // [<$name Commands>]::StartPhysCommandParserCmd(cmd) => <StartCommand as IsCommand<S>>::usable_at_runtime(cmd)
                        $([<$name Commands>]::$native_command_parser(cmd) => <<$native_command_parser as NativeCommandParser<S>>::OutputCommand as IsCommand<S>>::usable_at_runtime(cmd)),+
                    }
                }

                fn run<CM, EDT, ET, SM>(&self, emu: &mut Emulator<CM, EDT, ET, S, SM>, input: &S::Input, ret_reg: Option<Regs>) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
                where
                    CM: CommandManager<S>,
                    ET: StdInstrumentationFilter + Unpin,
                    EDT: EmulatorDriverTuple<CM, S, SM>,
                    S: UsesInput + Unpin,
                    SM: IsSnapshotManager
                {
                    match self {
                        // [<$name Commands>]::StartPhysCommandParserCmd(cmd) => cmd.run(emu, input, ret_reg)
                        $([<$name Commands>]::$native_command_parser(cmd) => cmd.run(emu, input, ret_reg)),+
                    }
                }
            }
        }
    }
}

pub struct NopCommandManager;

impl<S> CommandManager<S> for NopCommandManager
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
        StartPhysCommandParser,
        StartVirtCommandParser,
        InputPhysCommandParser,
        InputVirtCommandParser,
        SaveCommandParser,
        LoadCommandParser,
        EndCommandParser,
        VersionCommandParser,
        VaddrFilterAllowRangeCommandParser
    ]
);

pub trait CommandManager<S>: Sized
where
    S: UsesInput,
{
    type Commands: IsCommand<S> + Clone;

    fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError>;
}

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_UNKNOWN.0 as u64, // Should not be used
    Ok = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_OK.0 as u64,           // Normal exit
    Crash = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_CRASH.0 as u64, // Crash reported in the VM
}

pub trait IsCommand<S>: Debug
where
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
    fn run<CM, EDT, ET, SM>(
        &self,
        emu: &mut Emulator<CM, EDT, ET, S, SM>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager;
}

#[cfg(emulation_mode = "systemmode")]
pub type PagingFilterCommand = FilterCommand<QemuInstrumentationPagingFilter>;

pub type AddressRangeFilterCommand = FilterCommand<QemuInstrumentationAddressRangeFilter>;

#[derive(Debug, Clone)]
pub enum CommandError {
    UnknownCommand(GuestReg),
    RWError(QemuRWError),
    VersionDifference(u64),
}

impl From<QemuRWError> for CommandError {
    fn from(error: QemuRWError) -> Self {
        CommandError::RWError(error)
    }
}

#[derive(Debug, Clone)]
pub struct NopCommand;

impl Display for NopCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NopCommand")
    }
}

impl<S> IsCommand<S> for NopCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run<CM, EDT, ET, SM>(
        &self,
        _emu: &mut Emulator<CM, EDT, ET, S, SM>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct SaveCommand;
impl<S> IsCommand<S> for SaveCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run<CM, EDT, ET, SM>(
        &self,
        emu: &mut Emulator<CM, EDT, ET, S, SM>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
        let qemu = emu.qemu();
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        let std_emu_driver = emu
            .drivers_mut()
            .match_first_type_mut::<StdEmulatorDriver>()
            .unwrap();

        std_emu_driver
            .set_snapshot_id(snapshot_id)
            .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

        #[cfg(emulation_mode = "systemmode")]
        {
            let emulator_modules = emu.modules_mut().modules_mut();

            let mut allowed_paging_ids = HashSet::new();

            let current_paging_id = qemu.current_cpu().unwrap().current_paging_id().unwrap();
            allowed_paging_ids.insert(current_paging_id);

            let paging_filter =
                HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(
                    emulator_modules,
                );

            *paging_filter = QemuInstrumentationPagingFilter::AllowList(allowed_paging_ids);
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand;

impl<S> IsCommand<S> for LoadCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run<CM, EDT, ET, SM>(
        &self,
        emu: &mut Emulator<CM, EDT, ET, S, SM>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
        let qemu = emu.qemu();
        let std_emu_driver = emu
            .drivers()
            .match_first_type::<StdEmulatorDriver>()
            .unwrap();

        let snapshot_id = std_emu_driver
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

impl<S> IsCommand<S> for InputCommand
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run<CM, EDT, ET, SM>(
        &self,
        emu: &mut Emulator<CM, EDT, ET, S, SM>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
        let qemu = emu.qemu();

        let ret_value = self.location.write(qemu, input.target_bytes().as_slice());

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

impl<S> IsCommand<S> for StartCommand
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run<CM, EDT, ET, SM>(
        &self,
        emu: &mut Emulator<CM, EDT, ET, S, SM>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
        let qemu = emu.qemu();
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        let std_emu_driver = emu
            .drivers_mut()
            .match_first_type_mut::<StdEmulatorDriver>()
            .unwrap();

        std_emu_driver
            .set_snapshot_id(snapshot_id)
            .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

        std_emu_driver
            .set_input_location(InputLocation::new(
                self.input_location.clone(),
                qemu.current_cpu().unwrap(),
                ret_reg,
            ))
            .unwrap();

        let ret_value = self
            .input_location
            .write(qemu, input.target_bytes().as_slice());

        if let Some(reg) = ret_reg {
            qemu.write_reg(reg, ret_value).unwrap();
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct EndCommand {
    exit_kind: Option<ExitKind>,
}

impl<S> IsCommand<S> for EndCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run<CM, EDT, ET, SM>(
        &self,
        emu: &mut Emulator<CM, EDT, ET, S, SM>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
        let emu_exit_handler = emu
            .drivers()
            .match_first_type::<StdEmulatorDriver>()
            .unwrap();
        let qemu = emu.qemu();

        let snapshot_id = emu_exit_handler
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

impl<S> IsCommand<S> for VersionCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run<CM, EDT, ET, SM>(
        &self,
        _emu: &mut Emulator<CM, EDT, ET, S, SM>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
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

#[derive(Debug, Clone)]
pub struct FilterCommand<T> {
    filter: T,
}

#[cfg(emulation_mode = "systemmode")]
impl<S> IsCommand<S> for PagingFilterCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run<CM, EDT, ET, SM>(
        &self,
        emu: &mut Emulator<CM, EDT, ET, S, SM>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
        let qemu_modules = emu.modules_mut().modules_mut();

        let paging_filter =
            HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(qemu_modules);

        *paging_filter = self.filter.clone();

        Ok(None)
    }
}

impl<S> IsCommand<S> for AddressRangeFilterCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    #[allow(clippy::type_complexity)] // TODO: refactor with correct type.
    fn run<CM, EDT, ET, SM>(
        &self,
        _emu: &mut Emulator<CM, EDT, ET, S, SM>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, S>>, EmulatorDriverError>
    where
        CM: CommandManager<S>,
        ET: StdInstrumentationFilter + Unpin,
        EDT: EmulatorDriverTuple<CM, S, SM>,
        S: UsesInput + Unpin,
        SM: IsSnapshotManager,
    {
        let qemu_modules = &mut ();

        let addr_range_filter =
            HasInstrumentationFilter::<QemuInstrumentationAddressRangeFilter>::filter_mut(
                qemu_modules,
            );

        *addr_range_filter = self.filter.clone();

        Ok(None)
    }
}

impl VersionCommand {
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self(version)
    }
}

impl<T> FilterCommand<T> {
    pub fn new(filter: T) -> Self {
        Self { filter }
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

impl Display for AddressRangeFilterCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Addr range filter: {:?}", self.filter,)
    }
}

#[cfg(emulation_mode = "systemmode")]
impl Display for PagingFilterCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Addr range filter: {:?}", self.filter,)
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
