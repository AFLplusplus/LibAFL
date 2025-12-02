//! # Nyx API Command handlers
//!
//! Nyx command handlers.
//! Makes it possible to run Nyx targets in `LibAFL` QEMU.
//! The [Nyx API](https://github.com/IntelLabs/kafl.targets/blob/master/nyx_api.h) refers to the hypercalls used in Nyx to communicate with the fuzzer, not to the fuzzer itself.
//! This is mostly a convenient way to run Nyx-compatible targets in `LibAFL` QEMU directly, without having to change a single bit of the target files.

use std::{
    fmt,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    mem::offset_of,
    ops::Range,
    ptr,
    slice::from_raw_parts,
};

use enum_map::EnumMap;
use libafl::{executors::ExitKind, inputs::HasTargetBytes};
use libafl_qemu_sys::{GuestAddr, GuestVirtAddr};
use libc::c_uint;
use paste::paste;

use crate::{
    Emulator, EmulatorDriverError, EmulatorDriverResult, EmulatorExitResult, GuestReg,
    InputLocation, IsSnapshotManager, Qemu, QemuMemoryChunk, Regs, StdEmulatorDriver,
    command::{CommandError, CommandManager, IsCommand, NativeCommandParser},
    emu::{InputSetter, StdInputSetter, nyx::NyxInputSetter},
    get_exit_arch_regs,
    modules::{EmulatorModuleTuple, utils::filters::HasStdFiltersTuple},
    sync_exit::ExitArgs,
};

pub mod parser;
use parser::{
    AcquireCommandParser, GetHostConfigCommandParser, GetPayloadCommandParser,
    NextPayloadCommandParser, PanicCommandParser, PrintfCommandParser, RangeSubmitCommandParser,
    ReleaseCommandParser, SetAgentConfigCommandParser, SubmitCR3CommandParser,
    SubmitPanicCommandParser, UserAbortCommandParser,
};

macro_rules! define_nyx_command_manager {
    ($name:ident, [$($command:ty),+], [$($native_command_parser:ty),+]) => {
        paste! {
            pub struct $name<S> {
                has_started: bool,
                phantom: PhantomData<S>,
            }

            impl<S> Clone for $name<S> {
                fn clone(&self) -> Self {
                    Self {
                        has_started: self.has_started,
                        phantom: PhantomData,
                    }
                }
            }

            impl<S> Debug for $name<S> {
                fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                    write!(f, "{} (has started? {:?})", stringify!($name), self.has_started)
                }
            }

            impl<S> Default for $name<S> {
                fn default() -> Self {
                    Self {
                        has_started: false,
                        phantom: PhantomData,
                    }
                }
            }

            impl<S> $name<S> {
                fn start(&mut self) -> bool {
                    let tmp = self.has_started;
                    self.has_started = true;
                    tmp
                }

                fn has_started(&self) -> bool {
                    self.has_started
                }
            }

            impl<C, ET, I, S, SM> CommandManager<C, StdEmulatorDriver, ET, I, S, SM> for $name<S>
            where
                ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
                I: HasTargetBytes + Unpin,
                S: Unpin,
                SM: IsSnapshotManager,
            {
                type Commands = [<$name Commands>];

                #[deny(unreachable_patterns)]
                fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError> {
                    let arch_regs_map: &'static EnumMap<ExitArgs, Regs> = get_exit_arch_regs();
                    let nyx_backdoor = qemu.read_reg(Regs::Rax)? as c_uint;
                    let cmd_id = qemu.read_reg(Regs::Rbx)? as c_uint;

                    // Check nyx backdoor correctness
                    debug_assert_eq!(nyx_backdoor, libvharness_sys::HYPERCALL_KAFL_RAX_ID);

                    match cmd_id {
                        // <StartPhysCommandParser as NativeCommandParser<S>>::COMMAND_ID => Ok(NyxCommandManagerCommands::StartPhysCommandParserCmd(<StartPhysCommandParser as NativeCommandParser<S>>::parse(qemu, arch_regs_map)?)),
                        $(<$native_command_parser as NativeCommandParser<C, Self, StdEmulatorDriver, ET, I, S, SM>>::COMMAND_ID => Ok(<$native_command_parser as NativeCommandParser<C, Self, StdEmulatorDriver, ET, I, S, SM>>::parse(qemu, arch_regs_map)?.into())),+,
                        _ => Err(CommandError::UnknownCommand(cmd_id.into())),
                    }
                }
            }

            #[derive(Debug, Clone)]
            pub enum [<$name Commands>]
            {
                // StartPhysCommand(StartPhysCommand)
                $($command($command)),+,
            }

            impl<C, ET, I, S, SM> IsCommand<C, $name<S>, StdEmulatorDriver, ET, I, S, SM> for [<$name Commands>]
            where
                ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
                I: HasTargetBytes + Unpin,
                S: Unpin,
                SM: IsSnapshotManager,
            {
                fn usable_at_runtime(&self) -> bool {
                    match self {
                        $([<$name Commands>]::$command(cmd) => <$command as IsCommand<C, $name<S>, StdEmulatorDriver, ET, I, S, SM>>::usable_at_runtime(cmd)),+
                    }
                }

                fn run(&self,
                    emu: &mut Emulator<C, $name<S>, StdEmulatorDriver, ET, I, S, SM>,
                    ret_reg: Option<Regs>
                ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
                    match self {
                        $([<$name Commands>]::$command(cmd) => cmd.run(emu, ret_reg)),+
                    }
                }
            }

            $(
                impl From<$command> for [<$name Commands>] {
                    fn from(cmd: $command) -> [<$name Commands>] {
                        [<$name Commands>]::$command(cmd)
                    }
                }
            )+
        }
    };
}

define_nyx_command_manager!(
    NyxCommandManager,
    [
        AcquireCommand,
        ReleaseCommand,
        GetHostConfigCommand,
        SetAgentConfigCommand,
        PrintfCommand,
        GetPayloadCommand,
        NextPayloadCommand,
        SubmitCR3Command,
        PanicCommand,
        SubmitPanicCommand,
        UserAbortCommand,
        RangeSubmitCommand
    ],
    [
        AcquireCommandParser,
        ReleaseCommandParser,
        GetHostConfigCommandParser,
        SetAgentConfigCommandParser,
        PrintfCommandParser,
        GetPayloadCommandParser,
        NextPayloadCommandParser,
        SubmitCR3CommandParser,
        SubmitPanicCommandParser,
        PanicCommandParser,
        UserAbortCommandParser,
        RangeSubmitCommandParser
    ]
);

#[derive(Debug, Clone)]
pub struct AcquireCommand;
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for AcquireCommand {
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct GetPayloadCommand {
    input_struct_location: GuestVirtAddr,
}

impl GetPayloadCommand {
    #[must_use]
    pub fn new(input_struct_location: GuestVirtAddr) -> Self {
        Self {
            input_struct_location,
        }
    }
}

impl<C, ET, I, S, SM> IsCommand<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for GetPayloadCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        let struct_addr = self.input_struct_location;
        let input_addr = self.input_struct_location
            + offset_of!(libvharness_sys::kAFL_payload, data) as GuestVirtAddr;

        let payload_struct_mem_chunk = QemuMemoryChunk::virt(
            struct_addr,
            size_of::<libvharness_sys::kAFL_payload>() as GuestReg,
            qemu.current_cpu().unwrap(),
        );
        let payload_mem_chunk = QemuMemoryChunk::virt(
            input_addr,
            emu.driver().input_setter().max_input_size() as GuestReg,
            qemu.current_cpu().unwrap(),
        );

        // Save input struct location for next runs
        <StdInputSetter as NyxInputSetter<I, S>>::set_input_struct_location(
            emu.driver_mut().input_setter_mut(),
            InputLocation::new(qemu, &payload_struct_mem_chunk, None),
        )
        .unwrap();

        // Save input location for next runs
        <StdInputSetter as InputSetter<I, S>>::set_input_location(
            emu.driver_mut().input_setter_mut(),
            InputLocation::new(qemu, &payload_mem_chunk, None),
        )
        .unwrap();

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct NextPayloadCommand;

impl<C, ET, I, S, SM> IsCommand<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for NextPayloadCommand
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        if !emu.command_manager_mut().start() {
            log::debug!("Creating snapshot.");

            // Snapshot VM
            let snapshot_id = emu.snapshot_manager_mut().save(qemu);

            // Set snapshot ID to restore to after fuzzing ends
            emu.driver_mut()
                .set_snapshot_id(snapshot_id)
                .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

            // Auto page filtering if option is enabled
            #[cfg(feature = "systemmode")]
            if emu.driver_mut().allow_page_on_start() {
                if let Some(paging_id) = qemu.current_cpu().unwrap().current_paging_id() {
                    log::info!("Filter: allow page ID {paging_id}.");
                    emu.modules_mut().modules_mut().allow_page_id_all(paging_id);
                }
            }

            // Make sure JIT cache is empty just before starting
            qemu.flush_jit();

            log::info!("Fuzzing starts");

            return Ok(Some(EmulatorDriverResult::ReturnToClient(
                EmulatorExitResult::FuzzingStarts,
            )));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct SubmitCR3Command;

impl<C, ET, I, S, SM> IsCommand<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for SubmitCR3Command
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        if let Some(current_cpu) = qemu.current_cpu() {
            if let Some(paging_id) = current_cpu.current_paging_id() {
                log::info!("Filter: allow page ID {paging_id}.");
                emu.modules_mut().modules_mut().allow_page_id_all(paging_id);
                Ok(None)
            } else {
                log::warn!("No paging id found for current cpu");
                Err(EmulatorDriverError::CommandError(CommandError::WrongUsage))
            }
        } else {
            log::error!("No current cpu found");
            Err(EmulatorDriverError::CommandError(CommandError::WrongUsage))
        }
    }
}

#[derive(Debug, Clone)]
pub struct RangeSubmitCommand {
    allowed_range: Range<GuestAddr>,
}

impl RangeSubmitCommand {
    pub fn new(allowed_range: Range<GuestAddr>) -> Self {
        Self { allowed_range }
    }
}

impl<C, ET, I, S, SM> IsCommand<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for RangeSubmitCommand
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        log::info!("Allow address range: {:#x?}", self.allowed_range);

        const EMPTY_RANGE: Range<GuestAddr> = 0..0;

        if self.allowed_range == EMPTY_RANGE {
            log::warn!(
                "The given range is {:#x?}, which is most likely invalid. It is most likely a guest error.",
                EMPTY_RANGE
            );
            log::warn!(
                "Hint: make sure the range is not getting optimized out (the volatile keyword may help you)."
            );
        }

        emu.modules_mut()
            .modules_mut()
            .allow_address_range_all(&self.allowed_range);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct PanicCommand;

impl<C, ET, I, S, SM> IsCommand<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for PanicCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        if !emu.command_manager_mut().has_started() {
            return Err(EmulatorDriverError::CommandError(
                CommandError::EndBeforeStart,
            ));
        }

        let snapshot_id = emu
            .driver_mut()
            .snapshot_id()
            .ok_or(EmulatorDriverError::SnapshotNotFound)?;

        log::debug!("Restoring snapshot");
        emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;

        emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

        Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Crash)))
    }
}

#[derive(Debug, Clone)]
pub struct SubmitPanicCommand;

impl<C, ET, I, S, SM> IsCommand<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for SubmitPanicCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        // TODO: add breakpoint to submit panic addr / page and associate it with a panic command
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct UserAbortCommand {
    content: String,
}

impl UserAbortCommand {
    pub fn new(content: String) -> Self {
        Self { content }
    }
}

impl<C, ET, I, S, SM> IsCommand<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for UserAbortCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        log::error!("Nyx Guest Abort: {}", self.content);

        Ok(Some(EmulatorDriverResult::ShutdownRequest))
    }
}

#[derive(Debug, Clone)]
pub struct ReleaseCommand;
impl<C, ET, I, S, SM> IsCommand<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for ReleaseCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, NyxCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        if emu.command_manager().has_started() {
            log::debug!("Release: end of fuzzing run. Restoring...");

            let snapshot_id = emu
                .driver_mut()
                .snapshot_id()
                .ok_or(EmulatorDriverError::SnapshotNotFound)?;

            log::debug!("Restoring snapshot");
            emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;

            #[cfg(feature = "paranoid_debug")]
            emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

            Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Ok)))
        } else {
            log::debug!("Early release. Skipping...");

            Ok(None)
        }
    }
}

#[derive(Debug, Clone)]
pub struct GetHostConfigCommand {
    host_config_location: QemuMemoryChunk,
}

impl GetHostConfigCommand {
    #[must_use]
    pub fn new(host_config_location: QemuMemoryChunk) -> Self {
        Self {
            host_config_location,
        }
    }
}

impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for GetHostConfigCommand {
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        // TODO: check this against fuzzer code
        let host_config = libvharness_sys::host_config_t {
            bitmap_size: 0,
            ijon_bitmap_size: 0,
            payload_buffer_size: 0,
            worker_id: 0,
            host_magic: libvharness_sys::NYX_HOST_MAGIC,
            host_version: libvharness_sys::NYX_HOST_VERSION,
        };

        let host_config_buf = unsafe {
            from_raw_parts(
                ptr::from_ref(&host_config) as *const u8,
                size_of::<libvharness_sys::host_config_t>(),
            )
        };

        let qemu = emu.qemu();

        self.host_config_location
            .write(qemu, host_config_buf)
            .unwrap();

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct PrintfCommand {
    content: String,
}

impl PrintfCommand {
    #[must_use]
    pub fn new(content: String) -> Self {
        Self { content }
    }
}

impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for PrintfCommand {
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        println!("hprintf: {}", self.content);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct SetAgentConfigCommand {
    agent_config: libvharness_sys::agent_config_t,
}

impl SetAgentConfigCommand {
    #[must_use]
    pub fn new(agent_config: libvharness_sys::agent_config_t) -> Self {
        Self { agent_config }
    }
}

impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for SetAgentConfigCommand {
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let agent_magic = self.agent_config.agent_magic;
        let agent_version = self.agent_config.agent_version;

        assert_eq!(agent_magic, libvharness_sys::NYX_AGENT_MAGIC);
        assert_eq!(agent_version, libvharness_sys::NYX_AGENT_VERSION);

        // TODO: use agent config

        Ok(None)
    }
}
