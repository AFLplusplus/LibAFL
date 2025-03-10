use std::{ffi::CStr, sync::OnceLock};

use enum_map::{EnumMap, enum_map};
use libafl::{executors::ExitKind, inputs::HasTargetBytes};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};
use libc::c_uint;

use crate::{
    GuestReg, IsSnapshotManager, Qemu, QemuMemoryChunk, Regs, StdEmulatorDriver,
    command::{
        AddressAllowCommand, CommandError, CommandManager, EndCommand, InputCommand, IsCommand,
        LoadCommand, LqprintfCommand, NativeExitKind, SaveCommand, StartCommand, StdCommandManager,
        TestCommand, VersionCommand, bindings,
    },
    modules::{EmulatorModuleTuple, utils::filters::HasStdFiltersTuple},
    sync_exit::ExitArgs,
};

#[cfg(all(
    any(cpu_target = "i386", cpu_target = "x86_64"),
    feature = "systemmode"
))]
pub mod nyx;

pub static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

pub trait NativeCommandParser<C, CM, ED, ET, I, S, SM> {
    type OutputCommand: IsCommand<C, CM, ED, ET, I, S, SM>;

    const COMMAND_ID: c_uint;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError>;
}

pub struct InputPhysCommandParser;
impl<C, CM, ED, ET, I, S, SM> NativeCommandParser<C, CM, ED, ET, I, S, SM>
    for InputPhysCommandParser
where
    I: HasTargetBytes,
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
impl<C, CM, ED, ET, I, S, SM> NativeCommandParser<C, CM, ED, ET, I, S, SM>
    for InputVirtCommandParser
where
    I: HasTargetBytes,
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

impl<C, ET, I, S, SM> NativeCommandParser<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for StartPhysCommandParser
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: HasTargetBytes + Unpin,
    S: Unpin,
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

impl<C, ET, I, S, SM> NativeCommandParser<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for StartVirtCommandParser
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: HasTargetBytes + Unpin,
    S: Unpin,
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
impl<C, CM, ET, I, S, SM> NativeCommandParser<C, CM, StdEmulatorDriver, ET, I, S, SM>
    for SaveCommandParser
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
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
impl<C, CM, ET, I, S, SM> NativeCommandParser<C, CM, StdEmulatorDriver, ET, I, S, SM>
    for LoadCommandParser
where
    CM: CommandManager<C, StdEmulatorDriver, ET, I, S, SM>,
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

impl<C, ET, I, S, SM> NativeCommandParser<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for EndCommandParser
where
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
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
impl<C, CM, ED, ET, I, S, SM> NativeCommandParser<C, CM, ED, ET, I, S, SM>
    for VersionCommandParser
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
impl<C, CM, ED, ET, I, S, SM> NativeCommandParser<C, CM, ED, ET, I, S, SM>
    for VaddrFilterAllowRangeCommandParser
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: Unpin,
    S: Unpin,
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
impl<C, CM, ED, ET, I, S, SM> NativeCommandParser<C, CM, ED, ET, I, S, SM> for LqprintfCommandParser
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    type OutputCommand = LqprintfCommand;
    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_LQPRINTF.0;

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

        let mem_chunk =
            QemuMemoryChunk::virt(buf_addr as GuestVirtAddr, total_size as GuestReg, cpu);

        let str_copy: Vec<u8> = mem_chunk.read_vec(qemu)?;

        let c_str: &CStr = CStr::from_bytes_with_nul(str_copy.as_slice()).unwrap();

        Ok(LqprintfCommand::new(c_str.to_str().unwrap().to_string()))
    }
}

pub struct TestCommandParser;
impl<C, CM, ED, ET, I, S, SM> NativeCommandParser<C, CM, ED, ET, I, S, SM> for TestCommandParser
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    type OutputCommand = TestCommand;
    const COMMAND_ID: c_uint = bindings::LibaflQemuCommand_LIBAFL_QEMU_COMMAND_TEST.0;

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
