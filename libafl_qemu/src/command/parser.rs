use std::{fmt::Debug, rc::Rc, sync::OnceLock};

use enum_map::{enum_map, EnumMap};
use libafl::{
    executors::ExitKind,
    inputs::HasTargetBytes,
    state::{HasExecutions, State},
};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};

use crate::{
    command::{
        bindings, CommandError, CommandManager, EndCommand, FilterCommand, InputCommand, IsCommand,
        LoadCommand, NativeExitKind, SaveCommand, StartCommand, VersionCommand,
    },
    sync_exit::ExitArgs,
    EmulatorExitHandler, EmulatorMemoryChunk, GuestReg, IsSnapshotManager, Qemu, QemuHelperTuple,
    QemuInstrumentationAddressRangeFilter, Regs, StdEmulatorExitHandler, StdInstrumentationFilter,
};

pub static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

pub trait NativeCommandParser<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn command_id(&self) -> GuestReg;

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, E, QT, S>>, CommandError>;
}

pub struct InputPhysCommandParser;
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S>
    for InputPhysCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_PHYS.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
        let input_phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(InputCommand::new(
            EmulatorMemoryChunk::phys(
                input_phys_addr,
                max_input_size,
                Some(qemu.current_cpu().unwrap()),
            ),
            qemu.current_cpu().unwrap(),
        )))
    }
}

pub struct InputVirtCommandParser;
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S>
    for InputVirtCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_VIRT.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
        let input_virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(InputCommand::new(
            EmulatorMemoryChunk::virt(input_virt_addr, max_input_size, qemu.current_cpu().unwrap()),
            qemu.current_cpu().unwrap(),
        )))
    }
}

pub struct StartPhysCommandParser;
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S>
    for StartPhysCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
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
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
        let input_phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(StartCommand::new(EmulatorMemoryChunk::phys(
            input_phys_addr,
            max_input_size,
            Some(qemu.current_cpu().unwrap()),
        ))))
    }
}

pub struct StartVirtCommandParser;
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S>
    for StartVirtCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
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
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
        let input_virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(StartCommand::new(EmulatorMemoryChunk::virt(
            input_virt_addr,
            max_input_size,
            qemu.current_cpu().unwrap(),
        ))))
    }
}

pub struct SaveCommandParser;
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S> for SaveCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_SAVE.0)
    }

    fn parse(
        &self,
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
        Ok(Rc::new(SaveCommand))
    }
}

pub struct LoadCommandParser;
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S> for LoadCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_LOAD.0)
    }

    fn parse(
        &self,
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
        Ok(Rc::new(LoadCommand))
    }
}

pub struct EndCommandParser;
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S> for EndCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_END.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
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
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S>
    for VersionCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VERSION.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
        let client_version = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;

        Ok(Rc::new(VersionCommand::new(client_version)))
    }
}

pub struct VaddrFilterAllowRangeCommandParser;
impl<CM, QT, S, SM> NativeCommandParser<CM, StdEmulatorExitHandler<SM>, QT, S>
    for VaddrFilterAllowRangeCommandParser
where
    CM: CommandManager<StdEmulatorExitHandler<SM>, QT, S>,
    QT: QemuHelperTuple<S> + StdInstrumentationFilter + Debug,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn command_id(&self) -> GuestReg {
        GuestReg::from(bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW.0)
    }

    fn parse(
        &self,
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Rc<dyn IsCommand<CM, StdEmulatorExitHandler<SM>, QT, S>>, CommandError> {
        let vaddr_start: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let vaddr_end: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(Rc::new(FilterCommand::new(
            #[allow(clippy::single_range_in_vec_init)]
            QemuInstrumentationAddressRangeFilter::AllowList(vec![vaddr_start..vaddr_end]),
        )))
    }
}
