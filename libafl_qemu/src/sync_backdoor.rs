use std::fmt::{Display, Formatter};

use enum_map::{enum_map, Enum, EnumMap};
use lazy_static::lazy_static;
use libafl::executors::ExitKind;
use num_enum::{FromPrimitive, TryFromPrimitive, TryFromPrimitiveError};

use crate::{
    Emulator, GuestAddrKind, GuestPhysAddr, GuestReg, GuestVirtAddr, Regs, SYNC_BACKDOOR_ARCH_REGS,
};

#[derive(Debug, Clone)]
pub enum SyncBackdoorError {
    UnknownCommand(GuestReg),
    RegError(String),
}

impl From<String> for SyncBackdoorError {
    fn from(error_string: String) -> Self {
        SyncBackdoorError::RegError(error_string)
    }
}

#[derive(Debug, Clone, Enum)]
pub enum SyncBackdoorArgs {
    Ret,
    Cmd,
    Arg1,
    Arg2,
    Arg3,
    Arg4,
    Arg5,
    Arg6,
}

// TODO: Move in a separate header file to have a central definition of native definitions,
// reusable in targets directly.
#[derive(Debug, Clone, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeSyncBackdoorCommand {
    Save = 0,      // Save the VM
    Load = 1,      // Reload the target without ending the run?
    InputVirt = 2, // The address is a virtual address using the paging currently running in the VM.
    InputPhys = 3, // The address is a physical address
    End = 4,       // Implies reloading of the target. The first argument gives the exit status.
    StartVirt = 5, // Shortcut for Save + InputVirt
    StartPhys = 6, // Shortcut for Save + InputPhys
}

#[derive(Debug, Clone, Enum, TryFromPrimitive)]
#[repr(u64)]
pub enum NativeExitKind {
    Unknown = 0, // Should not be used
    Ok = 1,      // Normal exit
    Crash = 2,   // Crash reported in the VM
}

lazy_static! {
    static ref EMU_EXIT_KIND_MAP: EnumMap<NativeExitKind, Option<ExitKind>> = enum_map! {
        NativeExitKind::Unknown    => None,
        NativeExitKind::Ok         => Some(ExitKind::Ok),
        NativeExitKind::Crash      => Some(ExitKind::Crash)
    };
}

impl From<TryFromPrimitiveError<NativeSyncBackdoorCommand>> for SyncBackdoorError {
    fn from(error: TryFromPrimitiveError<NativeSyncBackdoorCommand>) -> Self {
        SyncBackdoorError::UnknownCommand(error.number)
    }
}

#[derive(Debug, Clone)]
pub struct CommandInput {
    addr: GuestAddrKind,
    max_input_size: GuestReg,
}

impl CommandInput {
    pub fn exec(&self, emu: &Emulator, backdoor: &SyncBackdoor, input: &[u8]) {
        match self.addr {
            GuestAddrKind::Physical(hwaddr) => unsafe { emu.write_phys_mem(hwaddr, input) },
            GuestAddrKind::Virtual(vaddr) => unsafe { emu.write_mem(vaddr, input) },
        };

        backdoor.ret(&emu, input.len().try_into().unwrap()).unwrap()
    }
}

impl Display for CommandInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:x} max nb bytes)", self.addr, self.max_input_size)
    }
}

#[derive(Debug, Clone)]
pub enum Command {
    Save,
    Load,
    Input(CommandInput),
    Start(CommandInput),
    Exit(Option<ExitKind>),
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Save => write!(f, "Save VM"),
            Command::Load => write!(f, "Reload VM"),
            Command::Input(command_input) => write!(f, "Set fuzzing input @{}", command_input),
            Command::Start(command_input) => {
                write!(f, "Start fuzzing with input @{}", command_input)
            }
            Command::Exit(exit_kind) => write!(f, "Exit of kind {:?}", exit_kind),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyncBackdoor {
    command: Command,
    arch_regs_map: &'static EnumMap<SyncBackdoorArgs, Regs>,
}

impl SyncBackdoor {
    pub fn command(&self) -> &Command {
        &self.command
    }

    pub fn ret(&self, emu: &Emulator, value: GuestReg) -> Result<(), SyncBackdoorError> {
        Ok(emu.write_reg(self.arch_regs_map[SyncBackdoorArgs::Ret], value)?)
    }
}

impl Display for SyncBackdoor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command)
    }
}

impl TryFrom<&Emulator> for SyncBackdoor {
    type Error = SyncBackdoorError;

    fn try_from(emu: &Emulator) -> Result<Self, Self::Error> {
        let arch_regs_map: &'static EnumMap<SyncBackdoorArgs, Regs> = &SYNC_BACKDOOR_ARCH_REGS;
        let cmd_id: GuestReg =
            emu.read_reg::<Regs, GuestReg>(arch_regs_map[SyncBackdoorArgs::Cmd])?;

        Ok(match cmd_id.try_into()? {
            NativeSyncBackdoorCommand::Save => SyncBackdoor {
                command: Command::Save,
                arch_regs_map,
            },
            NativeSyncBackdoorCommand::Load => SyncBackdoor {
                command: Command::Load,
                arch_regs_map,
            },
            NativeSyncBackdoorCommand::InputVirt => {
                let virt_addr: GuestVirtAddr =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg1])?;
                let max_input_size: GuestReg =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::Input(CommandInput {
                        addr: GuestAddrKind::Virtual(virt_addr),
                        max_input_size,
                    }),
                    arch_regs_map,
                }
            }
            NativeSyncBackdoorCommand::InputPhys => {
                let phys_addr: GuestPhysAddr =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg1])?;
                let max_input_size: GuestReg =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::Input(CommandInput {
                        addr: GuestAddrKind::Physical(phys_addr),
                        max_input_size,
                    }),
                    arch_regs_map,
                }
            }
            NativeSyncBackdoorCommand::End => {
                let native_exit_kind: GuestReg =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg1])?;
                let native_exit_kind: Result<NativeExitKind, _> = native_exit_kind.try_into();

                let exit_kind = native_exit_kind
                    .ok()
                    .map(|k| EMU_EXIT_KIND_MAP[k])
                    .flatten();

                SyncBackdoor {
                    command: Command::Exit(exit_kind),
                    arch_regs_map,
                }
            }
            NativeSyncBackdoorCommand::StartPhys => {
                let input_phys_addr: GuestPhysAddr =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg1])?;
                let max_input_size: GuestReg =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::Start(CommandInput {
                        addr: GuestAddrKind::Physical(input_phys_addr),
                        max_input_size,
                    }),
                    arch_regs_map,
                }
            }
            NativeSyncBackdoorCommand::StartVirt => {
                let input_virt_addr: GuestVirtAddr =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg1])?;
                let max_input_size: GuestReg =
                    emu.read_reg(arch_regs_map[SyncBackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::Start(CommandInput {
                        addr: GuestAddrKind::Virtual(input_virt_addr),
                        max_input_size,
                    }),
                    arch_regs_map,
                }
            }
        })
    }
}
