use std::{
    fmt,
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
        EmulatorModuleTuple, HasInstrumentationFilter, QemuInstrumentationAddressRangeFilter,
        StdInstrumentationFilter,
    },
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
                phantom: PhantomData<S>,
            }

            impl<S> Clone for $name<S> {
                fn clone(&self) -> Self {
                    Self {
                        phantom: PhantomData
                    }
                }
            }

            impl<S> Debug for $name<S> {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    write!(f, stringify!($name))
                }
            }

            impl<S> Default for $name<S> {
                fn default() -> Self {
                    Self {
                        phantom: PhantomData
                    }
                }
            }

            impl<ET, S, SM> CommandManager<StdEmulatorDriver, ET, S, SM> for $name<S>
            where
                ET: EmulatorModuleTuple<S> + StdInstrumentationFilter,
                S: UsesInput + Unpin,
                S::Input: HasTargetBytes,
                SM: IsSnapshotManager,
            {
                type Commands = [<$name Commands>];

                fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError> {
                    let arch_regs_map: &'static EnumMap<ExitArgs, Regs> = get_exit_arch_regs();
                    let cmd_id = qemu.read_reg::<Regs, GuestReg>(arch_regs_map[ExitArgs::Cmd])? as c_uint;

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
                ET: EmulatorModuleTuple<S> + StdInstrumentationFilter,
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
                    driver: &mut StdEmulatorDriver,
                    input: &S::Input,
                    ret_reg: Option<Regs>
                ) -> Result<Option<EmulatorDriverResult<$name<S>, StdEmulatorDriver, ET, S, SM>>, EmulatorDriverError> {
                    match self {
                        $([<$name Commands>]::$command(cmd) => cmd.run(emu, driver, input, ret_reg)),+
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
        AddressRangeFilterCommand
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
        VaddrFilterAllowRangeCommandParser
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
        driver: &mut ED,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError>;
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
        _driver: &mut ED,
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
    ET: EmulatorModuleTuple<S> + StdInstrumentationFilter,
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
        driver: &mut StdEmulatorDriver,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, StdEmulatorDriver, ET, S, SM>>, EmulatorDriverError>
    {
        let qemu = emu.qemu();
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        driver
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
        driver: &mut StdEmulatorDriver,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, StdEmulatorDriver, ET, S, SM>>, EmulatorDriverError>
    {
        let qemu = emu.qemu();

        let snapshot_id = driver
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
        _driver: &mut ED,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
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

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorDriver, ET, S, SM> for StartCommand
where
    CM: CommandManager<StdEmulatorDriver, ET, S, SM>,
    S: UsesInput,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorDriver, ET, S, SM>,
        driver: &mut StdEmulatorDriver,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, StdEmulatorDriver, ET, S, SM>>, EmulatorDriverError>
    {
        let qemu = emu.qemu();
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        driver
            .set_snapshot_id(snapshot_id)
            .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

        driver
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

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorDriver, ET, S, SM> for EndCommand
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
        driver: &mut StdEmulatorDriver,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, StdEmulatorDriver, ET, S, SM>>, EmulatorDriverError>
    {
        let qemu = emu.qemu();

        let snapshot_id = driver
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
        _driver: &mut ED,
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

#[derive(Debug, Clone)]
pub struct FilterCommand<T> {
    filter: T,
}

#[cfg(emulation_mode = "systemmode")]
impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for PagingFilterCommand
where
    ET: StdInstrumentationFilter + Unpin,
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, ED, ET, S, SM>,
        _driver: &mut ED,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        let qemu_modules = emu.modules_mut().modules_mut();

        let paging_filter =
            HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(qemu_modules);

        *paging_filter = self.filter.clone();

        Ok(None)
    }
}

impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for AddressRangeFilterCommand
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
        _driver: &mut ED,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
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
