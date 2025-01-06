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
    ptr,
    slice::from_raw_parts,
};

use enum_map::EnumMap;
use libafl::{
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
};
use libafl_qemu_sys::GuestVirtAddr;
use libc::c_uint;
use paste::paste;

use crate::{
    command::{
        parser::nyx::{
            AcquireCommandParser, GetHostConfigCommandParser, GetPayloadCommandParser,
            NextPayloadCommandParser, PrintfCommandParser, ReleaseCommandParser,
            SetAgentConfigCommandParser,
        },
        CommandError, CommandManager, IsCommand, NativeCommandParser,
    },
    get_exit_arch_regs,
    modules::EmulatorModuleTuple,
    sync_exit::ExitArgs,
    Emulator, EmulatorDriverError, EmulatorDriverResult, GuestReg, InputLocation,
    IsSnapshotManager, NyxEmulatorDriver, Qemu, QemuMemoryChunk, Regs,
};

pub(crate) mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(unused_mut)]
    #![allow(unused)]
    #![allow(unused_variables)]
    #![allow(clippy::all)]
    #![allow(clippy::pedantic)]

    include!(concat!(env!("OUT_DIR"), "/nyx_bindings.rs"));
}

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

            impl<ET, S, SM> CommandManager<NyxEmulatorDriver, ET, S, SM> for $name<S>
            where
                ET: EmulatorModuleTuple<S>,
                S: UsesInput + Unpin,
                S::Input: HasTargetBytes,
                SM: IsSnapshotManager,
            {
                type Commands = [<$name Commands>];

                #[deny(unreachable_patterns)]
                fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError> {
                    let arch_regs_map: &'static EnumMap<ExitArgs, Regs> = get_exit_arch_regs();
                    let nyx_backdoor = qemu.read_reg(arch_regs_map[ExitArgs::Cmd])? as c_uint;

                    // Check nyx backdoor correctness
                    debug_assert_eq!(nyx_backdoor, 0x1f);

                    let cmd_id = qemu.read_reg(arch_regs_map[ExitArgs::Arg1])? as c_uint;

                    match cmd_id {
                        // <StartPhysCommandParser as NativeCommandParser<S>>::COMMAND_ID => Ok(StdCommandManagerCommands::StartPhysCommandParserCmd(<StartPhysCommandParser as NativeCommandParser<S>>::parse(qemu, arch_regs_map)?)),
                        $(<$native_command_parser as NativeCommandParser<Self, NyxEmulatorDriver, ET, S, SM>>::COMMAND_ID => Ok(<$native_command_parser as NativeCommandParser<Self, NyxEmulatorDriver, ET, S, SM>>::parse(qemu, arch_regs_map)?.into())),+,
                        _ => Err(CommandError::UnknownCommand(cmd_id.into())),
                    }
                }
            }

            #[derive(Clone, Debug)]
            pub enum [<$name Commands>]
            {
                // StartPhysCommand(StartPhysCommand)
                $($command($command)),+,
            }

            impl<ET, S, SM> IsCommand<$name<S>, NyxEmulatorDriver, ET, S, SM> for [<$name Commands>]
            where
                ET: EmulatorModuleTuple<S>,
                S: UsesInput + Unpin,
                S::Input: HasTargetBytes,
                SM: IsSnapshotManager,
            {
                fn usable_at_runtime(&self) -> bool {
                    match self {
                        $([<$name Commands>]::$command(cmd) => <$command as IsCommand<$name<S>, NyxEmulatorDriver, ET, S, SM>>::usable_at_runtime(cmd)),+
                    }
                }

                fn run(&self,
                    emu: &mut Emulator<$name<S>, NyxEmulatorDriver, ET, S, SM>,
                    state: &mut S,
                    input: &S::Input,
                    ret_reg: Option<Regs>
                ) -> Result<Option<EmulatorDriverResult<$name<S>, NyxEmulatorDriver, ET, S, SM>>, EmulatorDriverError> {
                    match self {
                        $([<$name Commands>]::$command(cmd) => cmd.run(emu, state, input, ret_reg)),+
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
        NextPayloadCommand
    ],
    [
        AcquireCommandParser,
        ReleaseCommandParser,
        GetHostConfigCommandParser,
        SetAgentConfigCommandParser,
        PrintfCommandParser,
        GetPayloadCommandParser,
        NextPayloadCommandParser
    ]
);

#[derive(Debug, Clone)]
pub struct AcquireCommand;
impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for AcquireCommand
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
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

impl<ET, S, SM> IsCommand<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM> for GetPayloadCommand
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<
        Option<EmulatorDriverResult<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>>,
        EmulatorDriverError,
    > {
        let qemu = emu.qemu();

        let struct_addr = self.input_struct_location;
        let input_addr =
            self.input_struct_location + offset_of!(bindings::kAFL_payload, data) as GuestVirtAddr;

        let payload_struct_mem_chunk = QemuMemoryChunk::virt(
            struct_addr,
            size_of::<bindings::kAFL_payload>() as GuestReg,
            qemu.current_cpu().unwrap(),
        );
        let payload_mem_chunk = QemuMemoryChunk::virt(
            input_addr,
            emu.driver().max_input_size() as GuestReg,
            qemu.current_cpu().unwrap(),
        );

        // Save input struct location for next runs
        emu.driver_mut()
            .set_input_struct_location(InputLocation::new(
                payload_struct_mem_chunk,
                qemu.current_cpu().unwrap(),
                None,
            ))
            .unwrap();

        // Save input location for next runs
        emu.driver_mut()
            .set_input_location(InputLocation::new(
                payload_mem_chunk,
                qemu.current_cpu().unwrap(),
                None,
            ))
            .unwrap();

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct NextPayloadCommand;

impl<ET, S, SM> IsCommand<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM> for NextPayloadCommand
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>,
        state: &mut S,
        input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<
        Option<EmulatorDriverResult<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>>,
        EmulatorDriverError,
    > {
        if emu.command_manager_mut().start() {
            return Err(EmulatorDriverError::CommandError(
                CommandError::StartedTwice,
            ));
        }

        let qemu = emu.qemu();

        // Snapshot VM
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        // Set snapshot ID to restore to after fuzzing ends
        emu.driver_mut()
            .set_snapshot_id(snapshot_id)
            .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

        // write nyx input to vm
        emu.driver().write_input(qemu, input)?;

        // Unleash hooks if locked
        if emu.driver_mut().unlock_hooks() {
            // Prepare hooks
            emu.modules_mut().first_exec_all(qemu, state);
            emu.modules_mut().pre_exec_all(qemu, state, input);
        }

        // Auto page filtering if option is enabled
        #[cfg(feature = "systemmode")]
        if emu.driver_mut().allow_page_on_start() {
            if let Some(page_id) = qemu.current_cpu().unwrap().current_paging_id() {
                emu.modules_mut().modules_mut().allow_page_id_all(page_id);
            }
        }

        #[cfg(feature = "x86_64")]
        if emu.driver_mut().is_process_only() {
            emu.modules_mut()
                .modules_mut()
                .allow_address_range_all(crate::PROCESS_ADDRESS_RANGE);
        }

        // Make sure JIT cache is empty just before starting
        qemu.flush_jit();

        log::info!("Fuzzing starts");
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct ReleaseCommand;
impl<ET, S, SM> IsCommand<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM> for ReleaseCommand
where
    ET: EmulatorModuleTuple<S>,
    S: UsesInput + Unpin,
    S::Input: HasTargetBytes,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<
        Option<EmulatorDriverResult<NyxCommandManager<S>, NyxEmulatorDriver, ET, S, SM>>,
        EmulatorDriverError,
    > {
        let qemu = emu.qemu();

        if emu.command_manager().has_started() {
            let snapshot_id = emu
                .driver_mut()
                .snapshot_id()
                .ok_or(EmulatorDriverError::SnapshotNotFound)?;

            emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;

            #[cfg(feature = "paranoid_debug")]
            emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

            Ok(Some(EmulatorDriverResult::EndOfRun(ExitKind::Ok)))
        } else {
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

impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for GetHostConfigCommand
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        // TODO: check this against fuzzer code
        let host_config = bindings::host_config_t {
            bitmap_size: 0,
            ijon_bitmap_size: 0,
            payload_buffer_size: 0,
            worker_id: 0,
            host_magic: bindings::NYX_HOST_MAGIC,
            host_version: bindings::NYX_HOST_VERSION,
        };

        let host_config_buf = unsafe {
            from_raw_parts(
                ptr::from_ref(&host_config) as *const u8,
                size_of::<bindings::host_config_t>(),
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

impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for PrintfCommand
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        println!("hprintf: {}", self.content);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct SetAgentConfigCommand {
    agent_config: bindings::agent_config_t,
}

impl SetAgentConfigCommand {
    #[must_use]
    pub fn new(agent_config: bindings::agent_config_t) -> Self {
        Self { agent_config }
    }
}

impl<CM, ED, ET, S, SM> IsCommand<CM, ED, ET, S, SM> for SetAgentConfigCommand
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        _emu: &mut Emulator<CM, ED, ET, S, SM>,
        _state: &mut S,
        _input: &S::Input,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<CM, ED, ET, S, SM>>, EmulatorDriverError> {
        let agent_magic = self.agent_config.agent_magic;
        let agent_version = self.agent_config.agent_version;

        assert_eq!(agent_magic, bindings::NYX_AGENT_MAGIC);
        assert_eq!(agent_version, bindings::NYX_AGENT_VERSION);

        // TODO: use agent config

        Ok(None)
    }
}
