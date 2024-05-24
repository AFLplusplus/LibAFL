#[cfg(emulation_mode = "systemmode")]
use std::collections::HashSet;
use std::{
    collections::HashMap,
    fmt::{Debug, Display, Error, Formatter},
    rc::Rc,
};

use enum_map::{Enum, EnumMap};
use libafl::{
    executors::ExitKind,
    inputs::HasTargetBytes,
    state::{HasExecutions, State},
};
use libafl_bolts::AsSlice;
use num_enum::TryFromPrimitive;

#[cfg(emulation_mode = "systemmode")]
use crate::QemuInstrumentationPagingFilter;
use crate::{
    command::parser::{
        EndCommandParser, InputPhysCommandParser, InputVirtCommandParser, LoadCommandParser,
        NativeCommandParser, SaveCommandParser, StartPhysCommandParser, StartVirtCommandParser,
        VaddrFilterAllowRangeCommandParser, VersionCommandParser,
    },
    executor::QemuExecutorState,
    get_exit_arch_regs,
    sync_exit::ExitArgs,
    Emulator, EmulatorExitHandler, EmulatorMemoryChunk, ExitHandlerError, ExitHandlerResult,
    GuestReg, HasInstrumentationFilter, InputLocation, IsFilter, IsSnapshotManager, Qemu,
    QemuHelperTuple, QemuInstrumentationAddressRangeFilter, Regs, StdEmulatorExitHandler,
    StdInstrumentationFilter, CPU,
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
        pub struct $name<QT, S, SM>
        where
            QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
            S: State + HasExecutions,
            S::Input: HasTargetBytes,
            SM: IsSnapshotManager,
        {
            native_command_parsers:
                HashMap<GuestReg, Box<dyn NativeCommandParser<Self, StdEmulatorExitHandler<SM>, QT, S>>>,
        }

        impl<QT, S, SM> $name<QT, S, SM>
        where
            QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
            S: State + HasExecutions,
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
                                QT,
                                S,
                            >,
                        >),*]
                    .into_iter(),
                );

                let mut parsers: HashMap<
                    GuestReg,
                    Box<dyn NativeCommandParser<Self, StdEmulatorExitHandler<SM>, QT, S>>,
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

        impl<QT, S, SM> CommandManager<StdEmulatorExitHandler<SM>, QT, S> for $name<QT, S, SM>
        where
            QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
            S: State + HasExecutions,
            S::Input: HasTargetBytes,
            SM: IsSnapshotManager,
        {
            fn parse(
                &self,
                qemu: Qemu,
            ) -> Result<Rc<dyn IsCommand<Self, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
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

        impl<QT, S, SM> Debug for $name<QT, S, SM>
        where
            QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
            S: State + HasExecutions,
            S::Input: HasTargetBytes,
            SM: IsSnapshotManager,
        {
            fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
                write!(f, stringify!($name))
            }
        }

        impl<QT, S, SM> Default for $name<QT, S, SM>
        where
            QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
            S: State + HasExecutions,
            S::Input: HasTargetBytes,
            SM: IsSnapshotManager,
        {
            fn default() -> Self {
                Self::new()
            }
        }
    };
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

pub trait CommandManager<E, QT, S>: Sized
where
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn parse(&self, qemu: Qemu) -> Result<Rc<dyn IsCommand<Self, E, QT, S>>, CommandError>;
}

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_UNKNOWN.0 as u64, // Should not be used
    Ok = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_OK.0 as u64,           // Normal exit
    Crash = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_CRASH.0 as u64, // Crash reported in the VM
}

pub trait IsCommand<CM, E, QT, S>: Debug + Display
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
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
        emu: &Emulator<CM, E, QT, S>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, E, QT, S>>, ExitHandlerError>;
}

#[cfg(emulation_mode = "systemmode")]
pub type PagingFilterCommand = FilterCommand<QemuInstrumentationPagingFilter>;

pub type AddressRangeFilterCommand = FilterCommand<QemuInstrumentationAddressRangeFilter>;

#[derive(Debug, Clone)]
pub enum CommandError {
    UnknownCommand(GuestReg),
    RegError(String),
    VersionDifference(u64),
}

impl From<String> for CommandError {
    fn from(error_string: String) -> Self {
        CommandError::RegError(error_string)
    }
}

#[derive(Debug, Clone)]
pub struct SaveCommand;

impl<CM, QT, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S> for SaveCommand
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<CM, StdEmulatorExitHandler<SM>, QT, S>,
        #[cfg(emulation_mode = "systemmode")] qemu_executor_state: &mut QemuExecutorState<QT, S>,
        #[cfg(not(emulation_mode = "systemmode"))] _qemu_executor_state: &mut QemuExecutorState<
            QT,
            S,
        >,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, QT, S>>, ExitHandlerError>
    {
        let qemu = emu.qemu();
        let emu_exit_handler = emu.exit_handler().borrow_mut();

        let snapshot_id = emu_exit_handler.snapshot_manager_borrow_mut().save(qemu);
        emu_exit_handler
            .set_snapshot_id(snapshot_id)
            .map_err(|_| ExitHandlerError::MultipleSnapshotDefinition)?;

        #[cfg(emulation_mode = "systemmode")]
        {
            let qemu_helpers = qemu_executor_state.hooks_mut().helpers_mut();

            let mut allowed_paging_ids = HashSet::new();

            let current_paging_id = qemu.current_cpu().unwrap().current_paging_id().unwrap();
            allowed_paging_ids.insert(current_paging_id);

            let paging_filter =
                HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(
                    qemu_helpers,
                );

            *paging_filter = QemuInstrumentationPagingFilter::AllowList(allowed_paging_ids);
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand;

impl<CM, QT, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S> for LoadCommand
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<CM, StdEmulatorExitHandler<SM>, QT, S>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, QT, S>>, ExitHandlerError>
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
    location: EmulatorMemoryChunk,
    cpu: CPU,
}

impl<CM, QT, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S> for InputCommand
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &Emulator<CM, StdEmulatorExitHandler<SM>, QT, S>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, QT, S>>, ExitHandlerError>
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
    input_location: EmulatorMemoryChunk,
}

impl<CM, QT, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S> for StartCommand
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<CM, StdEmulatorExitHandler<SM>, QT, S>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, QT, S>>, ExitHandlerError>
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

impl<CM, QT, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S> for EndCommand
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<CM, StdEmulatorExitHandler<SM>, QT, S>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, QT, S>>, ExitHandlerError>
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

impl<CM, QT, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S> for VersionCommand
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &Emulator<CM, StdEmulatorExitHandler<SM>, QT, S>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, QT, S>>, ExitHandlerError>
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
pub struct FilterCommand<T>
where
    T: IsFilter + Debug,
{
    filter: T,
}

#[cfg(emulation_mode = "systemmode")]
impl<CM, QT, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S> for PagingFilterCommand
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &Emulator<CM, StdEmulatorExitHandler<SM>, QT, S>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, QT, S>>, ExitHandlerError>
    {
        let qemu_helpers = qemu_executor_state.hooks_mut().helpers_mut();

        let paging_filter =
            HasInstrumentationFilter::<QemuInstrumentationPagingFilter>::filter_mut(qemu_helpers);

        *paging_filter = self.filter.clone();

        Ok(None)
    }
}

impl<CM, QT, S, SM> IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S> for AddressRangeFilterCommand
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    #[allow(clippy::type_complexity)] // TODO: refactor with correct type.
    fn run(
        &self,
        _emu: &Emulator<CM, StdEmulatorExitHandler<SM>, QT, S>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult<CM, StdEmulatorExitHandler<SM>, QT, S>>, ExitHandlerError>
    {
        let qemu_helpers = qemu_executor_state.hooks_mut().helpers_mut();

        let addr_range_filter =
            HasInstrumentationFilter::<QemuInstrumentationAddressRangeFilter>::filter_mut(
                qemu_helpers,
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

impl<T> FilterCommand<T>
where
    T: IsFilter + Debug,
{
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
    pub fn new(input_location: EmulatorMemoryChunk) -> Self {
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
    pub fn new(location: EmulatorMemoryChunk, cpu: CPU) -> Self {
        Self { location, cpu }
    }
}
