use std::{rc::Rc, sync::OnceLock};

use enum_map::{enum_map, EnumMap};
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};

use crate::{
    command::{
        bindings, CommandError, EndCommand, FilterCommand, InputCommand, IsCommand, LoadCommand,
        NativeExitKind, SaveCommand, StartCommand, VersionCommand,
    },
    modules::{QemuInstrumentationAddressRangeFilter, StdInstrumentationFilter},
    sync_exit::ExitArgs,
    GuestReg, IsSnapshotManager, Qemu, QemuMemoryChunk, Regs, StdEmulatorExitHandler,
};

pub static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

pub trait NativeCommandParser<CM, EH, ET, S>
where
    S: UsesInput,
{
    fn command_id(&self) -> GuestReg;

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, EH, ET, S>>, CommandError>;
}

pub struct InputPhysCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S>
    for InputPhysCommandParser
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_PHYS.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
        let input_phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(InputCommand::new(
            QemuMemoryChunk::phys(
                input_phys_addr,
                max_input_size,
                Some(qemu.current_cpu().unwrap()),
            ),
            qemu.current_cpu().unwrap(),
        )))
    }
}

pub struct InputVirtCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S>
    for InputVirtCommandParser
where
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_VIRT.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
        let input_virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(InputCommand::new(
            QemuMemoryChunk::virt(input_virt_addr, max_input_size, qemu.current_cpu().unwrap()),
            qemu.current_cpu().unwrap(),
        )))
    }
}

pub struct StartPhysCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S>
    for StartPhysCommandParser
where
    S: UsesInput,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_START_PHYS.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
        let input_phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(StartCommand::new(QemuMemoryChunk::phys(
            input_phys_addr,
            max_input_size,
            Some(qemu.current_cpu().unwrap()),
        ))))
    }
}

pub struct StartVirtCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S>
    for StartVirtCommandParser
where
    S: UsesInput,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_START_VIRT.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
        let input_virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(StartCommand::new(QemuMemoryChunk::virt(
            input_virt_addr,
            max_input_size,
            qemu.current_cpu().unwrap(),
        ))))
    }
}

pub struct SaveCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S> for SaveCommandParser
where
    ET: StdInstrumentationFilter + Unpin,
    S: UsesInput + Unpin,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_SAVE.0)
    }

    fn parse(
        &self,
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
        Ok(Rc::new(SaveCommand))
    }
}

pub struct LoadCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S> for LoadCommandParser
where
    S: UsesInput,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_LOAD.0)
    }

    fn parse(
        &self,
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
        Ok(Rc::new(LoadCommand))
    }
}

pub struct EndCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S> for EndCommandParser
where
    S: UsesInput,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_END.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
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

        Ok(Rc::new(EndCommand::new(exit_kind)))
    }
}

pub struct VersionCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S>
    for VersionCommandParser
where
    S: UsesInput,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VERSION.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
        let client_version = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;

        Ok(Rc::new(VersionCommand::new(client_version)))
    }
}

pub struct VaddrFilterAllowRangeCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, ET, S>
    for VaddrFilterAllowRangeCommandParser
where
    S: UsesInput,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, ET, S>>, CommandError> {
        let vaddr_start: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let vaddr_end: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(FilterCommand::new(
            #[allow(clippy::single_range_in_vec_init)]
            QemuInstrumentationAddressRangeFilter::AllowList(vec![vaddr_start..vaddr_end]),
        )))
    }
}
