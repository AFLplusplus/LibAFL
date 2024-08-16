use std::sync::OnceLock;

use enum_map::{enum_map, EnumMap};
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};
use libc::c_uint;

use crate::{
    command::{
        bindings, CommandError, EndCommand, FilterCommand, InputCommand, IsCommand, LoadCommand,
        NativeExitKind, SaveCommand, StartCommand, VersionCommand,
    },
    modules::QemuInstrumentationAddressRangeFilter,
    sync_exit::ExitArgs,
    GuestReg, Qemu, QemuMemoryChunk, Regs,
};

pub static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

pub trait NativeCommandParser<S>
where
    S: UsesInput,
{
    type OutputCommand: IsCommand<S>;

    const COMMAND_ID: c_uint;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError>;
}

pub struct InputPhysCommandParser;
impl<S> NativeCommandParser<S> for InputPhysCommandParser
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = InputCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_PHYS.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let input_phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(InputCommand::new(
            QemuMemoryChunk::phys(
                input_phys_addr,
                max_input_size,
                Some(qemu.current_cpu().unwrap()),
            ),
            qemu.current_cpu().unwrap(),
        ))
    }
}

pub struct InputVirtCommandParser;
impl<S> NativeCommandParser<S> for InputVirtCommandParser
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = InputCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_VIRT.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let input_virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(InputCommand::new(
            QemuMemoryChunk::virt(input_virt_addr, max_input_size, qemu.current_cpu().unwrap()),
            qemu.current_cpu().unwrap(),
        ))
    }
}

pub struct StartPhysCommandParser;

impl<S> NativeCommandParser<S> for StartPhysCommandParser
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = StartCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_START_PHYS.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let input_phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(StartCommand::new(QemuMemoryChunk::phys(
            input_phys_addr,
            max_input_size,
            Some(qemu.current_cpu().unwrap()),
        )))
    }
}

pub struct StartVirtCommandParser;

impl<S> NativeCommandParser<S> for StartVirtCommandParser
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = StartCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_START_VIRT.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let input_virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(StartCommand::new(QemuMemoryChunk::virt(
            input_virt_addr,
            max_input_size,
            qemu.current_cpu().unwrap(),
        )))
    }
}

pub struct SaveCommandParser;
impl<S> NativeCommandParser<S> for SaveCommandParser
where
    S: UsesInput,
{
    type OutputCommand = SaveCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_SAVE.0;

    fn parse(
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        Ok(SaveCommand)
    }
}

pub struct LoadCommandParser;
impl<S> NativeCommandParser<S> for LoadCommandParser
where
    S: UsesInput,
{
    type OutputCommand = LoadCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_LOAD.0;

    fn parse(
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        Ok(LoadCommand)
    }
}

pub struct EndCommandParser;

impl<S> NativeCommandParser<S> for EndCommandParser
where
    S: UsesInput,
{
    type OutputCommand = EndCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_END.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let native_exit_kind: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let native_exit_kind: Result<NativeExitKind, _> = u64::from(native_exit_kind).try_into();

        let exit_kind = native_exit_kind.ok().and_then(|k| {
            EMU_EXIT_KIND_MAP.get_or_init(|| {
                enum_map! {
                    NativeExitKind::Unknown => None,
                    NativeExitKind::Ok      => Some(ExitKind::Ok),
                    NativeExitKind::Crash   => Some(ExitKind::Crash)
                }
            })[k]
        });

        Ok(EndCommand::new(exit_kind))
    }
}

pub struct VersionCommandParser;
impl<S> NativeCommandParser<S> for VersionCommandParser
where
    S: UsesInput,
{
    type OutputCommand = VersionCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VERSION.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let client_version = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;

        Ok(VersionCommand::new(client_version))
    }
}

pub struct VaddrFilterAllowRangeCommandParser;
impl<S> NativeCommandParser<S> for VaddrFilterAllowRangeCommandParser
where
    S: UsesInput,
{
    type OutputCommand = FilterCommand<QemuInstrumentationAddressRangeFilter>;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let vaddr_start: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let vaddr_end: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(FilterCommand::new(
            #[allow(clippy::single_range_in_vec_init)]
            QemuInstrumentationAddressRangeFilter::AllowList(vec![vaddr_start..vaddr_end]),
        ))
    }
}
