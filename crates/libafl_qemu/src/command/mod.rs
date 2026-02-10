use std::{
    ffi::c_uint,
    fmt::{self, Debug, Display, Formatter},
};

use enum_map::EnumMap;

use crate::{
    Emulator, EmulatorDriverError, EmulatorDriverResult, GuestReg, Qemu, QemuRWError, Regs,
    sync_exit::ExitArgs,
};

#[cfg(not(feature = "nyx"))]
pub mod lqemu;
#[cfg(all(
    not(feature = "nyx"),
    feature = "systemmode",
    not(feature = "usermode")
))]
pub use lqemu::SetMapCommand;
#[cfg(not(feature = "nyx"))]
pub use lqemu::{
    AddressAllowCommand, EndCommand, LoadCommand, LqemuCommandManager, LqprintfCommand,
    SaveCommand, StartCommand, TestCommand, VersionCommand,
};

#[cfg(feature = "nyx")]
pub mod nyx;
#[cfg(feature = "nyx")]
pub use nyx::{
    AcquireCommand, GetHostConfigCommand, GetPayloadCommand, NextPayloadCommand, NyxCommandManager,
    PanicCommand, PrintfCommand, RangeSubmitCommand, ReleaseCommand, SetAgentConfigCommand,
    SubmitCR3Command, SubmitPanicCommand, UserAbortCommand,
};

#[cfg(not(feature = "nyx"))]
pub type StdCommandManager<S> = LqemuCommandManager<S>;
#[cfg(feature = "nyx")]
pub type StdCommandManager<S> = NyxCommandManager<S>;

#[macro_export]
macro_rules! define_std_command_manager_bound {
    ($name:ident, $input_bound:ty, [$($command:ty),+], [$($native_command_parser:ty),+]) => {
        define_std_command_manager_inner!($name, ($input_bound,), [$($command),+], [$($native_command_parser),+]);
    };
}

#[macro_export]
macro_rules! define_std_command_manager_type {
    ($name:ident, $input_type:ty, [$($command:ty),+], [$($native_command_parser:ty),+]) => {
        define_std_command_manager_inner!($name, (), [$($command),+], [$($native_command_parser),+], $input_type);
    };
}

#[macro_export]
macro_rules! define_std_command_manager_inner {
    ($name:ident, ($($input_bound:ty,)?), [$($command:ty),+], [$($native_command_parser:ty),+]$(, $input_type:ty)?) => {
        paste! {
            pub use [< $name:snake >]::$name;

            mod [< $name:snake >] {
                use super::*;

                use std::{
                    fmt,
                    fmt::{Debug, Formatter},
                    marker::PhantomData,
                };
                use enum_map::EnumMap;
                use $crate::{
                    command::{IsStdCommandManager, CommandManager, CommandError, NativeCommandParser, IsCommand}, get_exit_arch_regs, modules::{utils::filters::HasStdFiltersTuple, EmulatorModuleTuple}, sync_exit::ExitArgs, Emulator, EmulatorDriverError, EmulatorDriverResult, IsSnapshotManager, Qemu, Regs, GenericEmulatorDriver, InputSetter,
                };
                use std::ffi::c_uint;

                pub struct $name<S> {
                    has_started: bool,
                    phantom: PhantomData<S>,
                }

                impl<S> IsStdCommandManager for $name<S> {
                    fn start(&mut self) -> bool {
                        let tmp = self.has_started;
                        self.has_started = true;
                        tmp
                    }

                    fn has_started(&self) -> bool {
                        self.has_started
                    }
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

                impl<C, ET, I, IS, S, SM> CommandManager<C, GenericEmulatorDriver<IS>, ET, I, S, SM> for $name<S>
                where
                    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
                    I: $($input_bound)? + Unpin,
                    IS: InputSetter<I, S>,
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
                            $(<$native_command_parser as NativeCommandParser<C, Self, GenericEmulatorDriver<IS>, ET, I, S, SM>>::COMMAND_ID => Ok(<$native_command_parser as NativeCommandParser<C, Self, GenericEmulatorDriver<IS>, ET, I, S, SM>>::parse(qemu, arch_regs_map)?.into())),+,
                            _ => Err(CommandError::UnknownCommand(cmd_id.into())),
                        }
                    }
                }

                #[derive(Clone, Debug)]
                #[expect(clippy::enum_variant_names)]
                pub enum [<$name Commands>]
                {
                    // StartPhysCommand(StartPhysCommand)
                    $($command($command)),+,
                }

                impl<C, ET, I, IS, S, SM> IsCommand<C, $name<S>, GenericEmulatorDriver<IS>, ET, I, S, SM> for [<$name Commands>]
                where
                    ET: EmulatorModuleTuple<I, S> + HasStdFiltersTuple,
                    I: $($input_bound)? + Unpin,
                    IS: InputSetter<I, S>,
                    S: Unpin,
                    SM: IsSnapshotManager,
                {
                    fn usable_at_runtime(&self) -> bool {
                        match self {
                            $([<$name Commands>]::$command(cmd) => <$command as IsCommand<C, $name<S>, GenericEmulatorDriver<IS>, ET, I, S, SM>>::usable_at_runtime(cmd)),+
                        }
                    }

                    fn run(&self,
                        emu: &mut Emulator<C, $name<S>, GenericEmulatorDriver<IS>, ET, I, S, SM>,
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
        }
    };
}

pub trait NativeCommandParser<C, CM, ED, ET, I, S, SM> {
    type OutputCommand: IsCommand<C, CM, ED, ET, I, S, SM>;

    const COMMAND_ID: c_uint;

    fn parse(
        qemu: Qemu,
        arch_regs_map: &'static EnumMap<ExitArgs, Regs>,
    ) -> Result<Self::OutputCommand, CommandError>;
}

pub trait IsStdCommandManager {
    /// Returns whether the command manager has been started already.
    fn has_started(&self) -> bool;

    /// Mark the command manager as started.
    /// it should return if it has been started before or not.
    fn start(&mut self) -> bool;
}

pub trait CommandManager<C, ED, ET, I, S, SM>: Sized + Debug {
    type Commands: IsCommand<C, Self, ED, ET, I, S, SM>;

    fn parse(&self, qemu: Qemu) -> Result<Self::Commands, CommandError>;
}

pub trait IsCommand<C, CM, ED, ET, I, S, SM>: Clone + Debug {
    /// Used to know whether the command can be run during a backdoor, or if it is necessary to go out of
    /// the QEMU VM to run the command.
    // TODO: Use const when stabilized
    fn usable_at_runtime(&self) -> bool;

    /// Command handler.
    ///     - `ret_reg`: The register in which the guest return value should be written, if any.
    /// Returns
    ///     - `InnerHandlerResult`: How the high-level handler should behave
    fn run(
        &self,
        emu: &mut Emulator<C, CM, ED, ET, I, S, SM>,
        ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError>;
}

#[derive(Debug, Clone)]
pub enum CommandError {
    UnknownCommand(GuestReg),
    RWError(QemuRWError),
    VersionDifference(u64, u64),
    TestDifference(GuestReg, GuestReg), // received, expected
    InvalidParameters,
    StartedTwice,
    EndBeforeStart,
    WrongUsage,
}

#[derive(Debug, Copy, Clone)]
pub struct NopCommandManager;
impl<C, ED, ET, I, S, SM> CommandManager<C, ED, ET, I, S, SM> for NopCommandManager {
    type Commands = NopCommand;

    fn parse(&self, _qemu: Qemu) -> Result<Self::Commands, CommandError> {
        Ok(NopCommand)
    }
}

impl From<QemuRWError> for CommandError {
    fn from(error: QemuRWError) -> Self {
        CommandError::RWError(error)
    }
}

#[derive(Debug, Copy, Clone)]
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
        _ret_reg: Option<Regs>,
    ) -> Result<Option<EmulatorDriverResult<C>>, EmulatorDriverError> {
        Ok(None)
    }
}
