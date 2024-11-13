use std::{ffi::CStr, sync::OnceLock};

use enum_map::{enum_map, EnumMap};
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_bolts::AsSliceMut;
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};
use libc::c_uint;

use crate::{
    command::{
        bindings, AddressAllowCommand, CommandError, CommandManager, EndCommand, InputCommand,
        IsCommand, LoadCommand, LqprintfCommand, NativeExitKind, SaveCommand, StartCommand,
        StdCommandManager, TestCommand, VersionCommand,
    },
    modules::EmulatorModuleTuple,
    sync_exit::ExitArgs,
    GuestReg, IsSnapshotManager, Qemu, QemuMemoryChunk, Regs, StdEmulatorDriver,
};

pub static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

pub trait NativeCommandParser<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    type OutputCommand: IsCommand<CM, ED, ET, S, SM>;

    const COMMAND_ID: c_uint;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError>;
}

pub struct InputPhysCommandParser;
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for InputPhysCommandParser
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = InputCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_PHYS.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let input_phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?.into();
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
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for InputVirtCommandParser
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = InputCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_INPUT_VIRT.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let input_virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?.into();
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(InputCommand::new(
            QemuMemoryChunk::virt(input_virt_addr, max_input_size, qemu.current_cpu().unwrap()),
            qemu.current_cpu().unwrap(),
        ))
    }
}

pub struct StartPhysCommandParser;

impl<ET, S, SM> NativeCommandParser<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM>
    for StartPhysCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = StartCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_START_PHYS.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let input_phys_addr: GuestPhysAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?.into();
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(StartCommand::new(QemuMemoryChunk::phys(
            input_phys_addr,
            max_input_size,
            Some(qemu.current_cpu().unwrap()),
        )))
    }
}

pub struct StartVirtCommandParser;

impl<ET, S, SM> NativeCommandParser<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM>
    for StartVirtCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = StartCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_START_VIRT.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let input_virt_addr: GuestVirtAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?.into();
        let max_input_size: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(StartCommand::new(QemuMemoryChunk::virt(
            input_virt_addr,
            max_input_size,
            qemu.current_cpu().unwrap(),
        )))
    }
}

pub struct SaveCommandParser;
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorDriver, ET, S, SM> for SaveCommandParser
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<StdEmulatorDriver, ET, S, SM>,
    S: UsesInput + Unpin,
    SM: IsSnapshotManager,
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
impl<CM, ET, S, SM> NativeCommandParser<CM, StdEmulatorDriver, ET, S, SM> for LoadCommandParser
where
    CM: CommandManager<StdEmulatorDriver, ET, S, SM>,
    S: UsesInput,
    SM: IsSnapshotManager,
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

impl<ET, S, SM> NativeCommandParser<StdCommandManager<S>, StdEmulatorDriver, ET, S, SM>
    for EndCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
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
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for VersionCommandParser
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    type OutputCommand = VersionCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VERSION.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let client_version = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?.into();

        Ok(VersionCommand::new(client_version))
    }
}

pub struct VaddrFilterAllowRangeCommandParser;
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM>
    for VaddrFilterAllowRangeCommandParser
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    type OutputCommand = AddressAllowCommand;

    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW.0;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let vaddr_start: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let vaddr_end: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])?;

        Ok(AddressAllowCommand::new(vaddr_start..vaddr_end))
    }
}

pub struct LqprintfCommandParser;
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for LqprintfCommandParser
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    type OutputCommand = LqprintfCommand;
    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_LQPRINTF.0;

    #[allow(clippy::uninit_vec)]
    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let buf_addr: GuestAddr = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;
        let str_size: usize = qemu
            .read_reg(arch_regs_map[ExitArgs::Arg2])?
            .try_into()
            .unwrap(); // without null byte
        let cpu = qemu.current_cpu().unwrap();

        let total_size = str_size + 1;

        let mut str_copy: Vec<u8> = unsafe {
            let mut res = Vec::<u8>::with_capacity(total_size);
            res.set_len(total_size);
            res
        };

        let mem_chunk =
            QemuMemoryChunk::virt(buf_addr as GuestVirtAddr, total_size as GuestReg, cpu);
        mem_chunk.read(qemu, str_copy.as_slice_mut())?;

        let c_str: &CStr = CStr::from_bytes_with_nul(str_copy.as_slice()).unwrap();

        Ok(LqprintfCommand::new(c_str.to_str().unwrap().to_string()))
    }
}

pub struct TestCommandParser;
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for TestCommandParser
where
    ET: EmulatorModuleTuple<S>,
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput + Unpin,
{
    type OutputCommand = TestCommand;
    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_TEST.0;

    #[allow(clippy::cast_sign_loss)]
    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let received_value: GuestReg = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])?;

        Ok(TestCommand::new(
            received_value,
            GuestReg::from(bindings::LIBAFL_QEMU_TEST_VALUE),
        ))
    }
}
