use std::{
    fmt::{Debug, Display, Error, Formatter},
    rc::Rc,
};

use enum_map::{Enum, EnumMap};
use hashbrown::HashMap;
#[cfg(emulation_mode = "systemmode")]
use hashbrown::HashSet;
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_bolts::AsSlice;
use num_enum::TryFromPrimitive;

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
    Emulator, ExitHandlerError, ExitHandlerResult, GuestReg, InputLocation, IsSnapshotManager,
    Qemu, QemuMemoryChunk, QemuRWError, Regs, StdEmulatorExitHandler, CPU,
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
        pub struct $name<ET, S, SM>
        where
            S: UsesInput,
        {
            native_command_parsers:
                HashMap<GuestReg, Box<dyn NativeCommandParser<Self, StdEmulatorExitHandler<SM>, ET, S>>>,
        }

        impl<ET, S, SM> $name<ET, S, SM>
        where
            ET: StdInstrumentationFilter + Unpin,
            S: UsesInput + Unpin,
            S::Input: HasTargetBytes,
            SM: IsSnapshotManager,
        {
            #[must_use]
            pub fn new() -> Self {
                let native_parsers = Box::new(
                    vec![$(Box::new($native_command_parser)
                        as Box<
                            dyn NativeCommandParser<
                                Self,
                                StdEmulatorExitHandler<SM>,
                                ET,
                                S,
                            >,
                        >),*]
                    .into_iter(),
                );

                let mut parsers: HashMap<
                    GuestReg,
                    Box<dyn NativeCommandParser<Self, StdEmulatorExitHandler<SM>, ET, S>>,
                > = HashMap::new();

                for parser in native_parsers {
                    assert!(parsers
                        .insert(parser.command_id(), parser)
                        .is_none(), "Trying to use native commands with the same ID");
                }

                Self {
                    native_command_parsers: parsers,
                }
            }
        }

        impl<ET, S, SM> CommandManager<StdEmulatorExitHandler<SM>, ET, S> for $name<ET, S, SM>
        where
            S: UsesInput,
        {
            fn parse(
                &self,
                qemu: Qemu,
            ) -> Result<Rc<dyn IsCommand<Self, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
                let arch_regs_map: &'static EnumMap<ExitArgs, Regs> = get_exit_arch_regs();
                let cmd_id: GuestReg = qemu.read_reg::<Regs, GuestReg>(arch_regs_map[ExitArgs::Cmd])?;

                let cmd_parser = self
                    .native_command_parsers
                    .get(&cmd_id)
                    .ok_or(CommandError::UnknownCommand(cmd_id))?;
                let cmd = cmd_parser.parse(qemu, arch_regs_map)?;

                Ok(cmd)
            }
        }

        impl<ET, S, SM> Debug for $name<ET, S, SM>
        where
            S: UsesInput,
        {
            fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
                write!(f, stringify!($name))
            }
        }

        impl<ET, S, SM> Default for $name<ET, S, SM>
        where
            ET: StdInstrumentationFilter + Unpin,
            S: UsesInput + Unpin,
            S::Input: HasTargetBytes,
            SM: IsSnapshotManager,
        {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

pub struct NopCommandManager;

impl<EH, ET, S> CommandManager<EH, ET, S> for NopCommandManager
where
    S: UsesInput,
{
    fn parse(&self, _qemu: Qemu) -> Result<Rc<dyn IsCommand<Self, EH, ET, S>>, CommandError> {
        Ok(Rc::new(NopCommand))
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

pub trait CommandManager<EH, ET, S>: Sized
where
    S: UsesInput,
{
    fn parse(&self, qemu: Qemu) -> Result<Rc<dyn IsCommand<Self, EH, ET, S>>, CommandError>;
}

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_UNKNOWN.0 as u64, // Should not be used
    Ok = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_OK.0 as u64,           // Normal exit
    Crash = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_CRASH.0 as u64, // Crash reported in the VM
}

pub trait IsCommand<CM, EH, ET, S>: Debug + Display
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
    fn run(
        &self,
        emu: &mut Emulator<CM, EH, ET, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, EH, ET, S>>, ExitHandlerError>;
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

impl<CM, EH, ET, S> IsCommand<CM, EH, ET, S> for NopCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, EH, ET, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, EH, ET, S>>, ExitHandlerError> {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct SaveCommand;

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S> for SaveCommand
where
    ET: StdInstrumentationFilter + Unpin,
    S: UsesInput + Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorExitHandler<SM>, ET, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, ET, S>>, ExitHandlerError>
    {
        let qemu = emu.qemu();

        {
            let emu_exit_handler = emu.exit_handler().borrow_mut();

            let snapshot_id = emu_exit_handler.snapshot_manager_borrow_mut().save(qemu);
            emu_exit_handler
                .set_snapshot_id(snapshot_id)
                .map_err(|_| ExitHandlerError::MultipleSnapshotDefinition)?;
        }

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

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S> for LoadCommand
where
    S: UsesInput,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorExitHandler<SM>, ET, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, ET, S>>, ExitHandlerError>
    {
        let qemu = emu.qemu();
        let emu_exit_handler = emu.exit_handler().borrow_mut();

        let snapshot_id = emu_exit_handler
            .snapshot_id()
            .ok_or(ExitHandlerError::SnapshotNotFound)?;

        emu_exit_handler
            .snapshot_manager_borrow_mut()
            .restore(&snapshot_id, qemu)?;

        #[cfg(feature = "paranoid_debug")]
        emu_exit_handler
            .snapshot_manager_borrow()
            .check(&snapshot_id, emu.qemu())?;

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct InputCommand {
    location: QemuMemoryChunk,
    cpu: CPU,
}

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S> for InputCommand
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorExitHandler<SM>, ET, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, ET, S>>, ExitHandlerError>
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

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S> for StartCommand
where
    S: UsesInput,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorExitHandler<SM>, ET, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, ET, S>>, ExitHandlerError>
    {
        let emu_exit_handler = emu.exit_handler().borrow_mut();
        let qemu = emu.qemu();
        let snapshot_id = emu_exit_handler.snapshot_manager_borrow_mut().save(qemu);

        emu_exit_handler
            .set_snapshot_id(snapshot_id)
            .map_err(|_| ExitHandlerError::MultipleSnapshotDefinition)?;

        emu_exit_handler
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
pub struct EndCommand(Option<ExitKind>);

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S> for EndCommand
where
    S: UsesInput,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorExitHandler<SM>, ET, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, ET, S>>, ExitHandlerError>
    {
        let emu_exit_handler = emu.exit_handler().borrow_mut();

        let snapshot_id = emu_exit_handler
            .snapshot_id()
            .ok_or(ExitHandlerError::SnapshotNotFound)?;

        emu_exit_handler
            .snapshot_manager_borrow_mut()
            .restore(&snapshot_id, emu.qemu())?;

        #[cfg(feature = "paranoid_debug")]
        emu_exit_handler
            .snapshot_manager_borrow()
            .check(&snapshot_id, emu.qemu())?;

        Ok(Some(ExitHandlerResult::EndOfRun(self.0.unwrap())))
    }
}

#[derive(Debug, Clone)]
pub struct VersionCommand(u64);

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S> for VersionCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, StdEmulatorExitHandler<SM>, ET, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, ET, S>>, ExitHandlerError>
    {
        let guest_version = self.0;

        if VERSION == guest_version {
            Ok(None)
        } else {
            Err(ExitHandlerError::CommandError(
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
impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S> for PagingFilterCommand
where
    ET: StdInstrumentationFilter + Unpin,
    S: UsesInput + Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, StdEmulatorExitHandler<SM>, ET, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, ET, S>>, ExitHandlerError>
    {
        let qemu_modules = emu.modules_mut().modules_mut();

        let paging_filter =
            HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(qemu_modules);

        *paging_filter = self.filter.clone();

        Ok(None)
    }
}

impl<CM, ET, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S> for AddressRangeFilterCommand
where
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    #[allow(clippy::type_complexity)] // TODO: refactor with correct type.
    fn run(
        &self,
        _emu: &mut Emulator<CM, StdEmulatorExitHandler<SM>, ET, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, ET, S>>, ExitHandlerError>
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
        write!(f, "Exit of kind {:?}", self.0)
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
        Self(exit_kind)
    }
}

impl InputCommand {
    #[must_use]
    pub fn new(location: QemuMemoryChunk, cpu: CPU) -> Self {
        Self { location, cpu }
    }
}
