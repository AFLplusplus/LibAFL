use std::{ffi::CStr, mem::transmute, sync::OnceLock};

use enum_map::EnumMap;
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_qemu_sys::GuestVirtAddr;
use libc::c_uint;

use crate::{
    command::{
        nyx::{
            bindings, AcquireCommand, GetHostConfigCommand, GetPayloadCommand, NextPayloadCommand,
            NyxCommandManager, PrintfCommand, ReleaseCommand, SetAgentConfigCommand,
        },
        parser::NativeCommandParser,
        CommandError, CommandManager, NativeExitKind,
    },
    modules::EmulatorModuleTuple,
    sync_exit::ExitArgs,
    IsSnapshotManager, NyxEmulatorDriver, Qemu, QemuMemoryChunk, Regs,
};

pub static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

pub struct AcquireCommandParser;
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for AcquireCommandParser
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = AcquireCommand;

    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_ACQUIRE;

    fn parse(
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        Ok(AcquireCommand)
    }
}

pub struct GetPayloadCommandParser;
impl<ET, S, SM> NativeCommandParser<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>
    for GetPayloadCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = GetPayloadCommand;

    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_GET_PAYLOAD;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let payload_addr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2]).unwrap() as GuestVirtAddr;

        Ok(GetPayloadCommand::new(payload_addr))
    }
}

pub struct NextPayloadCommandParser;
impl<ET, S, SM> NativeCommandParser<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>
    for NextPayloadCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = NextPayloadCommand;

    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_NEXT_PAYLOAD;

    fn parse(
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        Ok(NextPayloadCommand)
    }
}

pub struct ReleaseCommandParser;
impl<ET, S, SM> NativeCommandParser<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>
    for ReleaseCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = ReleaseCommand;

    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_RELEASE;

    fn parse(
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        Ok(ReleaseCommand)
    }
}

pub struct GetHostConfigCommandParser;
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for GetHostConfigCommandParser
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = GetHostConfigCommand;

    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_GET_HOST_CONFIG;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let host_config_addr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])? as GuestVirtAddr;

        Ok(GetHostConfigCommand::new(QemuMemoryChunk::virt(
            host_config_addr,
            GuestVirtAddr::try_from(size_of::<bindings::host_config_t>()).unwrap(),
            qemu.current_cpu().unwrap(),
        )))
    }
}

pub struct SetAgentConfigCommandParser;
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for SetAgentConfigCommandParser
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = SetAgentConfigCommand;

    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_SET_AGENT_CONFIG;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let agent_config_addr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])? as GuestVirtAddr;

        let mut agent_config_buf: [u8; size_of::<bindings::agent_config_t>()] =
            [0; size_of::<bindings::agent_config_t>()];

        qemu.read_mem(agent_config_addr, &mut agent_config_buf)?;

        let agent_config: bindings::agent_config_t = unsafe { transmute(agent_config_buf) };

        Ok(SetAgentConfigCommand::new(agent_config))
    }
}

pub struct PrintfCommandParser;
impl<CM, ED, ET, S, SM> NativeCommandParser<CM, ED, ET, S, SM> for PrintfCommandParser
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
    S::Input: HasTargetBytes,
{
    type OutputCommand = PrintfCommand;

    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_PRINTF;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let str_addr = qemu.read_reg(arch_regs_map[ExitArgs::Arg2])? as GuestVirtAddr;

        let mut msg_chunk: [u8; bindings::HPRINTF_MAX_SIZE as usize] =
            [0; bindings::HPRINTF_MAX_SIZE as usize];
        qemu.read_mem(str_addr, &mut msg_chunk)?;

        let cstr = CStr::from_bytes_until_nul(&msg_chunk).unwrap();

        Ok(PrintfCommand::new(cstr.to_str().unwrap().to_string()))
    }
}
