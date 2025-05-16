use std::{
    fmt,
    fmt::{Debug, Display, Formatter},
    marker::PhantomData,
    ops::Range,
};

use enum_map::{Enum, EnumMap};
use libafl::{executors::ExitKind, inputs::HasTargetBytes};
use libafl_bolts::AsSlice;
use libafl_qemu_sys::GuestAddr;
#[cfg(feature = "systemmode")]
use libafl_qemu_sys::GuestPhysAddr;
use libc::c_uint;
use num_enum::TryFromPrimitive;
use paste::paste;

use crate::{
    CPU, Emulator, EmulatorDriverError, EmulatorDriverResult, GuestReg, InputLocation,
    IsSnapshotManager, Qemu, QemuMemoryChunk, QemuRWError, Regs, StdEmulatorDriver,
    command::parser::{
        EndCommandParser, InputPhysCommandParser, InputVirtCommandParser, LoadCommandParser,
        LqprintfCommandParser, NativeCommandParser, SaveCommandParser, StartPhysCommandParser,
        StartVirtCommandParser, TestCommandParser, VaddrFilterAllowRangeCommandParser,
        VersionCommandParser,
    },
    get_exit_arch_regs,
    modules::{EmulatorModuleTuple, utils::filters::HasStdFiltersTuple},
    sync_exit::ExitArgs,
};

#[cfg(all(
    any(cpu_target = "i386", cpu_target = "x86_64"),
    feature = "systemmode"
))]
pub mod nyx;
pub mod parser;

mod bindings {
    #![expect(non_upper_case_globals)]
    #![expect(non_camel_case_types)]
    #![expect(non_snake_case)]
    #![expect(unused)]
    #![expect(clippy::all)]
    #![expect(clippy::pedantic)]
    #![allow(unsafe_op_in_unsafe_fn)]

    include!(concat!(env!("OUT_DIR"), "/libafl_qemu_bindings.rs"));
}

pub const VERSION: u64 = bindings::LIBAFL_QEMU_HDR_VERSION_NUMBER as u64;

macro_rules! define_std_command_manager {
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
                    let cmd_id = qemu.read_reg(arch_regs_map[ExitArgs::Cmd])? as c_uint;

                    match cmd_id {
                        // <StartPhysCommandParser as NativeCommandParser<S>>::COMMAND_ID => Ok(StdCommandManagerCommands::StartPhysCommandParserCmd(<StartPhysCommandParser as NativeCommandParser<S>>::parse(qemu, arch_regs_map)?)),
                        $(<$native_command_parser as NativeCommandParser<C, Self, StdEmulatorDriver, ET, I, S, SM>>::COMMAND_ID => Ok(<$native_command_parser as NativeCommandParser<C, Self, StdEmulatorDriver, ET, I, S, SM>>::parse(qemu, arch_regs_map)?.into())),+,
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
                    state: &mut S,
                    input: &I,
                    ret_reg: Option<Regs>
                ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
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

pub trait CommandManager<C, ED, ET, I, S, SM>: Sized + Debug {
    type Commands: IsCommand<C, Self, ED, ET, I, S, SM>;

    fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError>;
}

#[derive(Clone, Debug)]
pub struct NopCommandManager;
impl<C, ED, ET, I, S, SM> CommandManager<C, ED, ET, I, S, SM> for NopCommandManager {
    type Commands = NopCommand;

    fn parse(&self, _qemu: Qemu) -> Result<Self::Commands, CommandError> {
        Ok(NopCommand)
    }
}

define_std_command_manager!(
    StdCommandManager,
    [
        StartCommand,
        InputCommand,
        SaveCommand,
        LoadCommand,
        EndCommand,
        VersionCommand,
        AddressAllowCommand,
        LqprintfCommand,
        TestCommand
    ],
    [
        StartPhysCommandParser,
        StartVirtCommandParser,
        InputPhysCommandParser,
        InputVirtCommandParser,
        SaveCommandParser,
        LoadCommandParser,
        EndCommandParser,
        VersionCommandParser,
        VaddrFilterAllowRangeCommandParser,
        LqprintfCommandParser,
        TestCommandParser
    ]
);

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_UNKNOWN.0 as u64, // Should not be used
    Ok = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_OK.0 as u64,           // Normal exit
    Crash = bindings::LibaflQemuEndStatus_LIBAFL_QEMU_END_CRASH.0 as u64, // Crash reported in the VM
}

pub trait IsCommand<C, CM, ED, ET, I, S, SM>: Clone + Debug {
    /// Used to know whether the command can be run during a backdoor, or if it is necessary to go out of
    /// the QEMU VM to run the command.
    // TODO: Use const when stabilized
    fn usable_at_runtime(&self) -> bool;

    /// Command handler.
    ///     - `input`: The input for the current emulator run.
    ///     - `ret_reg`: The register in which the guest return value should be written, if any.
    /// Returns
    ///     - `InnerHandlerResult`: How the high-level handler should behave
    fn run(
        &self,
        emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        state: &mut S,
        input: &I,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError>;
}

#[derive(Debug, Clone)]
pub enum CommandError {
    UnknownCommand(GuestReg),
    RWError(QemuRWError),
    VersionDifference(u64),
    TestDifference(GuestReg, GuestReg), // received, expected
    StartedTwice,
    EndBeforeStart,
    WrongUsage,
}

impl From<QemuRWError> for CommandError {
    fn from(error: QemuRWError) -> Self {
        CommandError::RWError(error)
    }
}

#[derive(Debug, Clone)]
pub struct NopCommand;

impl Display for NopCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "NopCommand")
    }
}

impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for NopCommand {
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct SaveCommand;
impl<C, CM, ET, I, S, SM> IsCommand<C, CM, StdEmulatorDriver, ET, I, S, SM> for SaveCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, StdEmulatorDriver, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();
        let snapshot_id = emu.snapshot_manager_mut().save(qemu);

        emu.driver_mut()
            .set_snapshot_id(snapshot_id)
            .map_err(|_| EmulatorDriverError::MultipleSnapshotDefinition)?;

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LoadCommand;

impl<C, CM, ET, I, S, SM> IsCommand<C, CM, StdEmulatorDriver, ET, I, S, SM> for LoadCommand
where
    // CM: CommandManager<C, StdEmulatorDriver, ET, I, S, SM>,
    // ET: EmulatorModuleTuple<I, S>,
    SM: IsSnapshotManager,
{
    fn usable_at_runtime(&self) -> bool {
        false
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, StdEmulatorDriver, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        let snapshot_id = emu
            .driver_mut()
            .snapshot_id()
            .ok_or(EmulatorDriverError::SnapshotNotFound)?;

        emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;

        #[cfg(feature = "paranoid_debug")]
        emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct InputCommand {
    location: QemuMemoryChunk,
    cpu: CPU,
}

impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for InputCommand
where
    I: HasTargetBytes,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _state: &mut S,
        input: &I,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let qemu = emu.qemu();

        let ret_value = self
            .location
            .write(qemu, input.target_bytes().as_slice())
            .unwrap();

        if let Some(reg) = ret_reg {
            self.cpu.write_reg(reg, ret_value).unwrap();
        }

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct StartCommand {
    input_location: QemuMemoryChunk,
}
impl<C, ET, I, S, SM> IsCommand<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for StartCommand
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
        emu: &mut Emulator<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        state: &mut S,
        input: &I,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
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

        // Save input location for next runs
        emu.driver_mut()
            .set_input_location(InputLocation::new(
                self.input_location.clone(),
                qemu.current_cpu().unwrap(),
                ret_reg,
            ))
            .unwrap();

        // Write input to input location
        let ret_value = self
            .input_location
            .write(qemu, input.target_bytes().as_slice())
            .unwrap();

        // Unleash hooks if locked
        if emu.driver_mut().unlock_hooks() {
            // Prepare hooks
            emu.modules_mut().first_exec_all(qemu, state);
            emu.modules_mut().pre_exec_all(qemu, state, input);
        }

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

        // Set input size in return register if there is any
        if let Some(reg) = ret_reg {
            qemu.write_reg(reg, ret_value).unwrap();
        }

        log::info!("Fuzzing starts");

        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct EndCommand {
    exit_kind: Option<ExitKind>,
}

impl<C, ET, I, S, SM> IsCommand<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>
    for EndCommand
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
        emu: &mut Emulator<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
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

        emu.snapshot_manager_mut().restore(qemu, &snapshot_id)?;

        #[cfg(feature = "paranoid_debug")]
        emu.snapshot_manager_mut().check(qemu, &snapshot_id)?;

        Ok(Some(EmulatorDriverResult::EndOfRun(
            self.exit_kind.unwrap(),
        )))
    }
}

#[derive(Debug, Clone)]
pub struct VersionCommand(u64);

impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for VersionCommand {
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        let guest_version = self.0;

        if VERSION == guest_version {
            Ok(None)
        } else {
            Err(EmulatorDriverError::CommandError(
                CommandError::VersionDifference(guest_version),
            ))
        }
    }
}

#[cfg(feature = "systemmode")]
#[derive(Debug, Clone)]
pub struct PageAllowCommand {
    page_id: GuestPhysAddr,
}

#[cfg(feature = "systemmode")]
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for PageAllowCommand
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        emu.modules_mut()
            .modules_mut()
            .allow_page_id_all(self.page_id);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct AddressAllowCommand {
    address_range: Range<GuestAddr>,
}
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for AddressAllowCommand
where
    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        emu.modules_mut()
            .modules_mut()
            .allow_address_range_all(&self.address_range);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct LqprintfCommand {
    content: String,
}
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for LqprintfCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        print!("LQPRINTF: {}", self.content);
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct TestCommand {
    expected_value: GuestReg,
    received_value: GuestReg,
}
impl<C, CM, ED, ET, I, S, SM> IsCommand<C, CM, ED, ET, I, S, SM> for TestCommand
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin,
    S: Unpin,
{
    fn usable_at_runtime(&self) -> bool {
        true
    }

    fn run(
        &self,
        _emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        _state: &mut S,
        _input: &I,
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        if self.expected_value == self.received_value {
            Ok(None)
        } else {
            Err(EmulatorDriverError::CommandError(
                CommandError::TestDifference(self.received_value, self.expected_value),
            ))
        }
    }
}

impl TestCommand {
    #[must_use]
    pub fn new(received_value: GuestReg, expected_value: GuestReg) -> Self {
        Self {
            expected_value,
            received_value,
        }
    }
}

impl LqprintfCommand {
    #[must_use]
    pub fn new(content: String) -> Self {
        Self { content }
    }
}

impl VersionCommand {
    #[must_use]
    pub fn new(version: u64) -> Self {
        Self(version)
    }
}

impl AddressAllowCommand {
    #[must_use]
    pub fn new(address_range: Range<GuestAddr>) -> Self {
        Self { address_range }
    }
}

impl Display for SaveCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Save VM")
    }
}

impl Display for LoadCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reload VM")
    }
}

impl Display for InputCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Set fuzzing input @{}", self.location.addr())
    }
}

impl Display for StartCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start fuzzing with input @{}",
            self.input_location.addr()
        )
    }
}

impl Display for EndCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Exit of kind {:?}", self.exit_kind)
    }
}

impl Display for VersionCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client version: {}", self.0)
    }
}

impl Display for AddressAllowCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Addr range allow: {:?}", self.address_range)
    }
}

#[cfg(feature = "systemmode")]
impl Display for PageAllowCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Allowed page: {:?}", self.page_id)
    }
}

impl StartCommand {
    #[must_use]
    pub fn new(input_location: QemuMemoryChunk) -> Self {
        Self { input_location }
    }
}

impl EndCommand {
    #[must_use]
    pub fn new(exit_kind: Option<ExitKind>) -> Self {
        Self { exit_kind }
    }
}

impl InputCommand {
    #[must_use]
    pub fn new(location: QemuMemoryChunk, cpu: CPU) -> Self {
        Self { location, cpu }
    }
}
