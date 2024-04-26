use std::{
    fmt::{Display, Formatter},
    sync::OnceLock,
};

use enum_map::{enum_map, Enum, EnumMap};
use libafl::{
    executors::ExitKind,
    state::{HasExecutions, State},
};
use libafl_qemu_sys::{GuestAddr, GuestPhysAddr, GuestVirtAddr};
use num_enum::TryFromPrimitiveError;

use crate::{
    command::{
        Command, EmulatorMemoryChunk, EndCommand, FilterCommand, InputCommand, LoadCommand,
        NativeBackdoorCommand, NativeExitKind, SaveCommand, StartCommand, VersionCommand,
    },
    get_backdoor_arch_regs, EmuExitHandler, Emulator, GuestReg, QemuHelperTuple,
    QemuInstrumentationAddressRangeFilter, Regs, CPU,
};

#[derive(Debug, Clone)]
pub enum SyncBackdoorError {
    UnknownCommand(GuestReg),
    RegError(String),
    VersionDifference(u64),
}

impl From<String> for SyncBackdoorError {
    fn from(error_string: String) -> Self {
        SyncBackdoorError::RegError(error_string)
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

static EMU_EXIT_KIND_MAP: OnceLock<EnumMap<NativeExitKind, Option<ExitKind>>> = OnceLock::new();

impl From<TryFromPrimitiveError<NativeBackdoorCommand>> for SyncBackdoorError {
    fn from(error: TryFromPrimitiveError<NativeBackdoorCommand>) -> Self {
        SyncBackdoorError::UnknownCommand(error.number.try_into().unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct SyncBackdoor {
    command: Command,
    arch_regs_map: &'static EnumMap<BackdoorArgs, Regs>,
}

impl SyncBackdoor {
    #[must_use]
    pub fn command(&self) -> &Command {
        &self.command
    }

    pub fn ret(&self, cpu: &CPU, value: GuestReg) -> Result<(), SyncBackdoorError> {
        Ok(cpu.write_reg(self.arch_regs_map[BackdoorArgs::Ret], value)?)
    }

    #[must_use]
    pub fn ret_reg(&self) -> Regs {
        self.arch_regs_map[BackdoorArgs::Ret]
    }
}

impl Display for SyncBackdoor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command)
    }
}

impl<QT, S, E> TryFrom<&Emulator<QT, S, E>> for SyncBackdoor
where
    E: EmuExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    type Error = SyncBackdoorError;

    #[allow(clippy::too_many_lines)]
    fn try_from(emu: &Emulator<QT, S, E>) -> Result<Self, Self::Error> {
        let arch_regs_map: &'static EnumMap<BackdoorArgs, Regs> = get_backdoor_arch_regs();
        let cmd_id: GuestReg = emu
            .qemu()
            .read_reg::<Regs, GuestReg>(arch_regs_map[BackdoorArgs::Cmd])?;

        Ok(match u64::from(cmd_id).try_into()? {
            NativeBackdoorCommand::Save => SyncBackdoor {
                command: Command::SaveCommand(SaveCommand),
                arch_regs_map,
            },
            NativeBackdoorCommand::Load => SyncBackdoor {
                command: Command::LoadCommand(LoadCommand),
                arch_regs_map,
            },
            NativeBackdoorCommand::InputVirt => {
                let virt_addr: GuestVirtAddr =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let max_input_size: GuestReg =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::InputCommand(InputCommand::new(EmulatorMemoryChunk::virt(
                        virt_addr,
                        max_input_size,
                        emu.qemu().current_cpu().unwrap().clone(),
                    ))),
                    arch_regs_map,
                }
            }
            NativeBackdoorCommand::InputPhys => {
                let phys_addr: GuestPhysAddr =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let max_input_size: GuestReg =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::InputCommand(InputCommand::new(EmulatorMemoryChunk::phys(
                        phys_addr,
                        max_input_size,
                        Some(emu.qemu().current_cpu().unwrap().clone()),
                    ))),
                    arch_regs_map,
                }
            }
            NativeBackdoorCommand::End => {
                let native_exit_kind: GuestReg =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
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

                SyncBackdoor {
                    command: Command::EndCommand(EndCommand::new(exit_kind)),
                    arch_regs_map,
                }
            }
            NativeBackdoorCommand::StartPhys => {
                let input_phys_addr: GuestPhysAddr =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let max_input_size: GuestReg =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::StartCommand(StartCommand::new(EmulatorMemoryChunk::phys(
                        input_phys_addr,
                        max_input_size,
                        Some(emu.qemu().current_cpu().unwrap().clone()),
                    ))),
                    arch_regs_map,
                }
            }
            NativeBackdoorCommand::StartVirt => {
                let input_virt_addr: GuestVirtAddr =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let max_input_size: GuestReg =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::StartCommand(StartCommand::new(EmulatorMemoryChunk::virt(
                        input_virt_addr,
                        max_input_size,
                        emu.qemu().current_cpu().unwrap().clone(),
                    ))),
                    arch_regs_map,
                }
            }
            NativeBackdoorCommand::Version => {
                let client_version = emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg1])?;

                SyncBackdoor {
                    command: Command::VersionCommand(VersionCommand::new(client_version)),
                    arch_regs_map,
                }
            }
            NativeBackdoorCommand::VaddrFilterAllowRange => {
                let vaddr_start: GuestAddr =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg1])?;
                let vaddr_end: GuestAddr =
                    emu.qemu().read_reg(arch_regs_map[BackdoorArgs::Arg2])?;

                SyncBackdoor {
                    command: Command::AddressRangeFilterCommand(FilterCommand::new(
                        #[allow(clippy::single_range_in_vec_init)]
                        QemuInstrumentationAddressRangeFilter::AllowList(vec![
                            vaddr_start..vaddr_end,
                        ]),
                    )),
                    arch_regs_map,
                }
            }
        })
    }
}
