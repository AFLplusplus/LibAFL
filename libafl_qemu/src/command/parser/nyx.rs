use std::{ffi::CStr, sync::OnceLock};

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
            NyxCommandManager, PanicCommand, PrintfCommand, RangeSubmitCommand, ReleaseCommand,
            SetAgentConfigCommand, SubmitCR3Command, SubmitPanicCommand, UserAbortCommand,
        },
        parser::NativeCommandParser,
        CommandError, CommandManager, NativeExitKind,
    },
    modules::EmulatorModuleTuple,
    sync_exit::ExitArgs,
    IsSnapshotManager, NyxEmulatorDriver, Qemu, QemuMemoryChunk, Regs,
};

fn get_guest_string(qemu: Qemu, string_ptr_reg: Regs) -> Result<String, CommandError> {
    let str_addr = qemu.read_reg(string_ptr_reg)? as GuestVirtAddr;

    let mut msg_chunk: [u8; bindings::HPRINTF_MAX_SIZE as usize] =
        [0; bindings::HPRINTF_MAX_SIZE as usize];
    qemu.read_mem(str_addr, &mut msg_chunk)?;

    Ok(CStr::from_bytes_until_nul(&msg_chunk)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string())
}

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
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let payload_addr = qemu.read_reg(Regs::Rcx).unwrap() as GuestVirtAddr;

        Ok(GetPayloadCommand::new(payload_addr))
    }
}

pub struct SubmitCR3CommandParser;
impl<ET, S, SM> NativeCommandParser<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>
    for SubmitCR3CommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = SubmitCR3Command;
    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_SUBMIT_CR3;

    fn parse(
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        Ok(SubmitCR3Command)
    }
}

pub struct RangeSubmitCommandParser;
impl<ET, S, SM> NativeCommandParser<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>
    for RangeSubmitCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = RangeSubmitCommand;
    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_RANGE_SUBMIT;

    fn parse(
        qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let allowed_range_addr = qemu.read_reg(Regs::Rcx)? as GuestVirtAddr;

        let allowed_range: [u64; 3] = unsafe { qemu.read_mem_val(allowed_range_addr)? };

        Ok(RangeSubmitCommand::new(allowed_range[0]..allowed_range[1]))
    }
}

pub struct SubmitPanicCommandParser;
impl<ET, S, SM> NativeCommandParser<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>
    for SubmitPanicCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = SubmitPanicCommand;
    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_SUBMIT_PANIC;

    fn parse(
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        Ok(SubmitPanicCommand)
    }
}

pub struct PanicCommandParser;
impl<ET, S, SM> NativeCommandParser<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>
    for PanicCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = PanicCommand;
    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_PANIC;

    fn parse(
        _qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        Ok(PanicCommand)
    }
}

pub struct UserAbortCommandParser;
impl<ET, S, SM> NativeCommandParser<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>
    for UserAbortCommandParser
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    type OutputCommand = UserAbortCommand;
    const COMMAND_ID: c_uint = bindings::HYPERCALL_KAFL_USER_ABORT;

    fn parse(
        qemu: Qemu,
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let msg = get_guest_string(qemu, Regs::Rcx)?;

        Ok(UserAbortCommand::new(msg))
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
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let host_config_addr = qemu.read_reg(Regs::Rcx)? as GuestVirtAddr;

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
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let agent_config_addr = qemu.read_reg(Regs::Rcx)? as GuestVirtAddr;

        let agent_config: bindings::agent_config_t =
            unsafe { qemu.read_mem_val(agent_config_addr)? };

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
        _arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError> {
        let msg = get_guest_string(qemu, Regs::Rcx)?;

        Ok(PrintfCommand::new(msg))
    }
}
