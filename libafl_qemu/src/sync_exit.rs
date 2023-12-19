use std::{
    fmt::{Display, Formatter},
    sync::OnceLock,
};

use enum_map::{enum_map, Enum, EnumMap};
use libafl::executors::ExitKind;
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use crate::{
    get_backdoor_arch_regs, Command, CommandInput, Emulator, GuestPhysAddr, GuestReg,
    GuestVirtAddr, IsEmuExitHandler, Regs, CPU,
};

mod bindings {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(unused_mut)]
    #![allow(unused)]
    #![allow(unused_variables)]
    #![allow(clippy::all)]
    #![allow(clippy::pedantic)]

    #[cfg(all(not(feature = "clippy"), target_os = "linux"))]
    include!(concat!(env!("OUT_DIR"), "/sync_exit_bindings.rs"));
}

pub const VERSION: u64 = bindings::LIBAFL_EXIT_VERSION_NUMBER as u64;

#[derive(Debug, Clone)]
pub enum SyncExitError {
    UnknownCommand(GuestReg),
    RegError(String),
    VersionDifference(u64),
}

impl From<String> for SyncExitError {
    fn from(error_string: String) -> Self {
        SyncExitError::RegError(error_string)
    }
}

#[derive(Debug, Clone, Enum)]
pub enum BackdoorArgs {
    Ret,
    Cmd,
    Arg1,
    Arg2,
    Arg3,
    Arg4,
    Arg5,
    Arg6,
}

#[derive(Debug, Clone, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeSyncExitCommand {
    StartVirt = bindings::LibaflExit_LIBAFL_EXIT_START_VIRT.0 as u64, // Shortcut for Save + InputVirt
    StartPhys = bindings::LibaflExit_LIBAFL_EXIT_START_PHYS.0 as u64, // Shortcut for Save + InputPhys
    InputVirt = bindings::LibaflExit_LIBAFL_EXIT_INPUT_VIRT.0 as u64, // The address is a virtual address using the paging currently running in the VM.
    InputPhys = bindings::LibaflExit_LIBAFL_EXIT_INPUT_PHYS.0 as u64, // The address is a physical address
    End = bindings::LibaflExit_LIBAFL_EXIT_END.0 as u64, // Implies reloading of the target. The first argument gives the exit status.
    Save = bindings::LibaflExit_LIBAFL_EXIT_SAVE.0 as u64, // Save the VM
    Load = bindings::LibaflExit_LIBAFL_EXIT_LOAD.0 as u64, // Reload the target without ending the run?
    Version = bindings::LibaflExit_LIBAFL_EXIT_VERSION.0 as u64, // Version of the bindings used in the target
}

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = bindings::LibaflExitEndStatus_LIBAFL_EXIT_END_UNKNOWN.0 as u64, // Should not be used
    Ok = bindings::LibaflExitEndStatus_LIBAFL_EXIT_END_OK.0 as u64,           // Normal exit
    Crash = bindings::LibaflExitEndStatus_LIBAFL_EXIT_END_CRASH.0 as u64, // Crash reported in the VM
}

static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

impl From<TryFromPrimitiveError<NativeSyncExitCommand>> for SyncExitError {
    fn from(error: TryFromPrimitiveError<NativeSyncExitCommand>) -> Self {
        SyncExitError::UnknownCommand(error.number.try_into().unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct SyncExit {
    command: Command,
    arch_regs_map: &'static EnumMap<BackdoorArgs, Regs>,
}

impl SyncExit {
    #[must_use]
    pub fn command(&self) -> &Command {
        &self.command
    }

    pub fn ret(&self, cpu: &CPU, value: GuestReg) -> Result<(), SyncExitError> {
        Ok(cpu.write_reg(self.arch_regs_map[BackdoorArgs::Ret], value)?)
    }
}

impl Display for SyncExit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command)
    }
}

impl<E> TryFrom<&Emulator<E>> for SyncExit
where
    E: IsEmuExitHandler,
{
    type Error = SyncExitError;

    fn try_from(emu: &Emulator<E>) -> Result<Self, Self::Error> {
        let arch_regs_map: &'static EnumMap<BackdoorArgs, Regs> = get_backdoor_arch_regs();
        let cmd_id: GuestReg = emu.read_reg::<Regs, GuestReg>(arch_regs_map[BackdoorArgs::Cmd])?;

        Ok(match u64::from(cmd_id).try_into()? {
            NativeSyncExitCommand::Save => SyncExit {
                command: Command::Save,
                arch_regs_map,
            },
            NativeSyncExitCommand::Load => SyncExit {
                command: Command::Load,
                arch_regs_map,
            },
            NativeSyncExitCommand::InputVirt => {
                let virt_addr: GuestVirtAddr = emu.read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let max_input_size: GuestReg = emu.read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncExit {
                    command: Command::Input(CommandInput::virt(
                        virt_addr,
                        max_input_size,
                        emu.current_cpu().unwrap().clone(),
                    )),
                    arch_regs_map,
                }
            }
            NativeSyncExitCommand::InputPhys => {
                let phys_addr: GuestPhysAddr = emu.read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let max_input_size: GuestReg = emu.read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncExit {
                    command: Command::Input(CommandInput::phys(
                        phys_addr,
                        max_input_size,
                        Some(emu.current_cpu().unwrap().clone()),
                    )),
                    arch_regs_map,
                }
            }
            NativeSyncExitCommand::End => {
                let native_exit_kind: GuestReg = emu.read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let native_exit_kind: Result<NativeExitKind, _> =
                    u64::from(native_exit_kind).try_into();

                let exit_kind = native_exit_kind.ok().and_then(|k| {
                    EMU_EXIT_KIND_MAP.get_or_init(|| {
                        enum_map! {
                            NativeExitKind::Unknown => None,
                            NativeExitKind::Ok      => Some(ExitKind::Ok),
                            NativeExitKind::Crash   => Some(ExitKind::Crash)
                        }
                    })[k]
                });

                SyncExit {
                    command: Command::Exit(exit_kind),
                    arch_regs_map,
                }
            }
            NativeSyncExitCommand::StartPhys => {
                let input_phys_addr: GuestPhysAddr =
                    emu.read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let max_input_size: GuestReg = emu.read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncExit {
                    command: Command::Start(CommandInput::phys(
                        input_phys_addr,
                        max_input_size,
                        Some(emu.current_cpu().unwrap().clone()),
                    )),
                    arch_regs_map,
                }
            }
            NativeSyncExitCommand::StartVirt => {
                let input_virt_addr: GuestVirtAddr =
                    emu.read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let max_input_size: GuestReg = emu.read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncExit {
                    command: Command::Start(CommandInput::virt(
                        input_virt_addr,
                        max_input_size,
                        emu.current_cpu().unwrap().clone(),
                    )),
                    arch_regs_map,
                }
            }
            NativeSyncExitCommand::Version => {
                let client_version = emu.read_reg(arch_regs_map[BackdoorArgs::Arg1])?;

                SyncExit {
                    command: Command::Version(client_version),
                    arch_regs_map,
                }
            }
        })
    }
}
