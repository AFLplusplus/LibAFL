#[cfg(emulation_mode = "systemmode")]
use std::collections::HashSet;
use std::{
    fmt::{Debug, Display, Formatter},
    sync::OnceLock,
};

use enum_map::{enum_map, Enum, EnumMap};
use libafl::{
    executors::ExitKind,
    inputs::HasTargetBytes,
    state::{HasExecutions, State},
};
use libafl_bolts::AsSlice;
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

#[cfg(emulation_mode = "systemmode")]
use crate::QemuInstrumentationPagingFilter;
use crate::{
    executor::QemuExecutorState, get_exit_arch_regs, sync_exit::ExitArgs, Emulator,
    EmulatorExitHandler, EmulatorMemoryChunk, ExitHandlerError, ExitHandlerResult, GuestReg,
    HasInstrumentationFilter, InputLocation, IsFilter, IsSnapshotManager, Qemu, QemuHelperTuple,
    QemuInstrumentationAddressRangeFilter, Regs, StdEmulatorExitHandler, StdInstrumentationFilter,
    CPU,
};

pub const VERSION: u64 = bindings::LIBAFL_QEMU_HDR_VERSION_NUMBER as u64;

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

#[derive(Debug, Clone, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeCommand {
    StartVirt = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_START_VIRT.0 as u64, // Shortcut for Save + InputVirt
    StartPhys = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_START_PHYS.0 as u64, // Shortcut for Save + InputPhys
    InputVirt = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_VIRT.0 as u64, // The address is a virtual address using the paging currently running in the VM.
    InputPhys = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_PHYS.0 as u64, // The address is a physical address
    End = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_END.0 as u64, // Implies reloading of the target. The first argument gives the exit status.
    Save = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_SAVE.0 as u64, // Save the VM
    Load = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_LOAD.0 as u64, // Reload the target without ending the run?
    Version = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VERSION.0 as u64, // Version of the bindings used in the target
    VaddrFilterAllowRange =
        bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW.0 as u64, // Allow given address range
}

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_UNKNOWN.0 as u64, // Should not be used
    Ok = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_OK.0 as u64,           // Normal exit
    Crash = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_CRASH.0 as u64, // Crash reported in the VM
}

pub trait IsCommand<QT, S, E>
where
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
    E: EmulatorExitHandler<QT, S>,
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
        emu: &Emulator<QT, S, E>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError>;
}

#[cfg(emulation_mode = "systemmode")]
pub type PagingFilterCommand = FilterCommand<QemuInstrumentationPagingFilter>;

pub type AddressRangeFilterCommand = FilterCommand<QemuInstrumentationAddressRangeFilter>;

#[derive(Debug, Clone)]
pub enum Command {
    SaveCommand(SaveCommand),
    LoadCommand(LoadCommand),
    InputCommand(InputCommand),
    StartCommand(StartCommand),
    EndCommand(EndCommand),
    VersionCommand(VersionCommand),
    #[cfg(emulation_mode = "systemmode")]
    PagingFilterCommand(PagingFilterCommand),
    AddressRangeFilterCommand(AddressRangeFilterCommand),
}

pub static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

#[derive(Debug, Clone)]
pub enum CommandError {
    UnknownCommand(GuestReg),
    RegError(String),
    VersionDifference(u64),
}

impl From<TryFromPrimitiveError<NativeCommand>> for CommandError {
    fn from(error: TryFromPrimitiveError<NativeCommand>) -> Self {
        CommandError::UnknownCommand(error.number.try_into().unwrap())
    }
}

impl From<String> for CommandError {
    fn from(error_string: String) -> Self {
        CommandError::RegError(error_string)
    }
}

impl TryFrom<Qemu> for Command {
    type Error = CommandError;

    #[allow(clippy::too_many_lines)]
    fn try_from(qemu: Qemu) -> Result<Self, Self::Error> {
        let arch_regs_map: &'static EnumMap<ExitArgs, Regs> = get_exit_arch_regs();
        let cmd_id: GuestReg = qemu.read_reg::<Regs, GuestReg>(arch_regs_map[ExitArgs::Cmd])?;

        Ok(match u64::from(cmd_id).try_into()? {
            NativeCommand::Save => Command::SaveCommand(SaveCommand),
            NativeCommand::Load => Command::LoadCommand(LoadCommand),
            NativeCommand::InputVirt => {
                let virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
                let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

                Command::InputCommand(InputCommand::new(
                    EmulatorMemoryChunk::virt(
                        virt_addr,
                        max_input_size,
                        qemu.current_cpu().unwrap(),
                    ),
                    qemu.current_cpu().unwrap(),
                ))
            }
            NativeCommand::InputPhys => {
                let phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
                let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

                Command::InputCommand(InputCommand::new(
                    EmulatorMemoryChunk::phys(
                        phys_addr,
                        max_input_size,
                        Some(qemu.current_cpu().unwrap()),
                    ),
                    qemu.current_cpu().unwrap(),
                ))
            }
            NativeCommand::End => {
                let native_exit_kind: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
                let native_exit_kind: Result<NativeExitKind, _> =
                    u64::from(native_exit_kind).try_into();

                let exit_kind = native_exit_kind.ok().and_then(|k| {
                    EMU_EXIT_KIND_MAP.get_or_init(|| {
                        enum_map! {
                            NativeExitKind::Unknown => None,
                            NativeExitKind::Ok      => Some(ExitKind::Ok),
                            NativeExitKind::Crash   => Some(ExitKind::Crash)
                        }
                    })[k]
                });

                Command::EndCommand(EndCommand::new(exit_kind))
            }
            NativeCommand::StartPhys => {
                let input_phys_addr: GuestPhysAddr =
                    qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
                let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

                Command::StartCommand(StartCommand::new(EmulatorMemoryChunk::phys(
                    input_phys_addr,
                    max_input_size,
                    Some(qemu.current_cpu().unwrap()),
                )))
            }
            NativeCommand::StartVirt => {
                let input_virt_addr: GuestVirtAddr =
                    qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
                let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

                Command::StartCommand(StartCommand::new(EmulatorMemoryChunk::virt(
                    input_virt_addr,
                    max_input_size,
                    qemu.current_cpu().unwrap(),
                )))
            }
            NativeCommand::Version => {
                let client_version = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;

                Command::VersionCommand(VersionCommand::new(client_version))
            }
            NativeCommand::VaddrFilterAllowRange => {
                let vaddr_start: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
                let vaddr_end: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

                Command::AddressRangeFilterCommand(FilterCommand::new(
                    #[allow(clippy::single_range_in_vec_init)]
                    QemuInstrumentationAddressRangeFilter::AllowList(vec![vaddr_start..vaddr_end]),
                ))
            }
        })
    }
}

// TODO: Replace with enum_dispatch implementation
impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for Command
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        match self {
            Command::SaveCommand(cmd) => {
                <SaveCommand as IsCommand<QT, S, StdEmulatorExitHandler<SM>>>::usable_at_runtime(
                    cmd,
                )
            }
            Command::LoadCommand(cmd) => {
                <LoadCommand as IsCommand<QT, S, StdEmulatorExitHandler<SM>>>::usable_at_runtime(
                    cmd,
                )
            }
            Command::InputCommand(cmd) => {
                <InputCommand as IsCommand<QT, S, StdEmulatorExitHandler<SM>>>::usable_at_runtime(
                    cmd,
                )
            }
            Command::StartCommand(cmd) => {
                <StartCommand as IsCommand<QT, S, StdEmulatorExitHandler<SM>>>::usable_at_runtime(
                    cmd,
                )
            }
            Command::EndCommand(cmd) => {
                <EndCommand as IsCommand<QT, S, StdEmulatorExitHandler<SM>>>::usable_at_runtime(cmd)
            }
            Command::VersionCommand(cmd) => {
                <VersionCommand as IsCommand<QT, S, StdEmulatorExitHandler<SM>>>::usable_at_runtime(
                    cmd,
                )
            }
            #[cfg(emulation_mode = "systemmode")]
            Command::PagingFilterCommand(cmd) => <PagingFilterCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::usable_at_runtime(cmd),
            Command::AddressRangeFilterCommand(cmd) => <AddressRangeFilterCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::usable_at_runtime(cmd),
        }
    }

    fn run(
        &self,
        emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
        match self {
            Command::SaveCommand(cmd) => <SaveCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::run(
                cmd, emu, qemu_executor_state, input, ret_reg
            ),
            Command::LoadCommand(cmd) => <LoadCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::run(
                cmd, emu, qemu_executor_state, input, ret_reg
            ),
            Command::InputCommand(cmd) => <InputCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::run(
                cmd, emu, qemu_executor_state, input, ret_reg
            ),
            Command::StartCommand(cmd) => <StartCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::run(
                cmd, emu, qemu_executor_state, input, ret_reg
            ),
            Command::EndCommand(cmd) => <EndCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::run(
                cmd, emu, qemu_executor_state, input, ret_reg
            ),
            Command::VersionCommand(cmd) => <VersionCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::run(
                cmd, emu, qemu_executor_state, input, ret_reg
            ),
            #[cfg(emulation_mode = "systemmode")]
            Command::PagingFilterCommand(cmd) => <PagingFilterCommand as IsCommand<
                QT,
                S,
                StdEmulatorExitHandler<SM>,
            >>::run(
                cmd, emu, qemu_executor_state, input, ret_reg
            ),
            Command::AddressRangeFilterCommand(cmd) => {
                <AddressRangeFilterCommand as IsCommand<QT, S, StdEmulatorExitHandler<SM>>>::run(
                    cmd,
                    emu,
                    qemu_executor_state,
                    input,
                    ret_reg,
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct SaveCommand;

impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for SaveCommand
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        #[cfg(emulation_mode = "systemmode")] qemu_executor_state: &mut QemuExecutorState<QT, S>,
        #[cfg(not(emulation_mode = "systemmode"))] _qemu_executor_state: &mut QemuExecutorState<
            QT,
            S,
        >,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
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
                HasInstrumentationFilter::<QemuInstrumentationPagingFilter, S>::filter_mut(
                    qemu_helpers,
                );

            *paging_filter = QemuInstrumentationPagingFilter::AllowList(allowed_paging_ids);
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand;

impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for LoadCommand
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
        let qemu = emu.qemu();
        let emu_exit_handler = emu.exit_handler().borrow_mut();

        let snapshot_id = emu_exit_handler
            .snapshot_id()
            .ok_or(ExitHandlerError::SnapshotNotFound)?;

        emu_exit_handler
            .snapshot_manager_borrow_mut()
            .restore(&snapshot_id, qemu)?;

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct InputCommand {
    location: EmulatorMemoryChunk,
    cpu: CPU,
}

impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for InputCommand
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
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

impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for StartCommand
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        input: &S::Input,
        ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
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

impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for EndCommand
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
        let emu_exit_handler = emu.exit_handler().borrow_mut();

        let snapshot_id = emu_exit_handler
            .snapshot_id()
            .ok_or(ExitHandlerError::SnapshotNotFound)?;

        emu_exit_handler
            .snapshot_manager_borrow_mut()
            .restore(&snapshot_id, emu.qemu())?;

        Ok(Some(ExitHandlerResult::EndOfRun(self.0.unwrap())))
    }
}

#[derive(Debug, Clone)]
pub struct VersionCommand(u64);

impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for VersionCommand
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        _qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
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
impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for PagingFilterCommand
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
        let qemu_helpers = qemu_executor_state.hooks_mut().helpers_mut();

        let paging_filter =
            HasInstrumentationFilter::<QemuInstrumentationPagingFilter, S>::filter_mut(
                qemu_helpers,
            );

        *paging_filter = self.filter.clone();

        Ok(None)
    }
}

impl<SM, QT, S> IsCommand<QT, S, StdEmulatorExitHandler<SM>> for AddressRangeFilterCommand
where
    SM: IsSnapshotManager,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter<S> + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    #[allow(clippy::type_complexity)] // TODO: refactor with correct type.
    fn run(
        &self,
        _emu: &Emulator<QT, S, StdEmulatorExitHandler<SM>>,
        qemu_executor_state: &mut QemuExecutorState<QT, S>,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<ExitHandlerResult>, ExitHandlerError> {
        let qemu_helpers = qemu_executor_state.hooks_mut().helpers_mut();

        let addr_range_filter =
            HasInstrumentationFilter::<QemuInstrumentationAddressRangeFilter, S>::filter_mut(
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

// TODO: rewrite with display implementation for each command.
impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::SaveCommand(_) => write!(f, "Save VM"),
            Command::LoadCommand(_) => write!(f, "Reload VM"),
            Command::InputCommand(input_command) => {
                write!(f, "Set fuzzing input @{}", input_command.location.addr())
            }
            Command::StartCommand(start_command) => {
                write!(
                    f,
                    "Start fuzzing with input @{}",
                    start_command.input_location.addr()
                )
            }
            Command::EndCommand(end_command) => write!(f, "Exit of kind {:?}", end_command.0),
            Command::VersionCommand(version_command) => {
                write!(f, "Client version: {}", version_command.0)
            }
            Command::AddressRangeFilterCommand(addr_range_filter) => {
                write!(f, "Addr range filter: {:?}", addr_range_filter.filter,)
            }
            #[cfg(emulation_mode = "systemmode")]
            Command::PagingFilterCommand(paging_filter) => {
                write!(f, "Addr range filter: {:?}", paging_filter.filter,)
            }
        }
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

impl Display for InputCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (0x{:x} max nb bytes)",
            self.location.addr(),
            self.location.size()
        )
    }
}
