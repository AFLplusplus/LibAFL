use std::fmt::{Debug, Formatter};

use enum_map::Enum;
use libafl::inputs::UsesInput;

use crate::{command::CommandManager, get_exit_arch_regs, GuestReg, Regs, CPU};

#[derive(Debug, Clone, Enum)]
pub enum ExitArgs {
    Ret,
    Cmd,
    Arg1,
    Arg2,
    Arg3,
    Arg4,
    Arg5,
    Arg6,
}

pub struct SyncExit<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    command: CM::Commands,
}

impl<CM, ED, ET, S, SM> Clone for SyncExit<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn clone(&self) -> Self {
        Self {
            command: self.command.clone(),
        }
    }
}

impl<CM, ED, ET, S, SM> Debug for SyncExit<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sync Exit")
    }
}

impl<CM, ED, ET, S, SM> SyncExit<CM, ED, ET, S, SM>
where
    CM: CommandManager<ED, ET, S, SM>,
    S: UsesInput,
{
    #[must_use]
    pub fn new(command: CM::Commands) -> Self {
        Self { command }
    }

    #[must_use]
    pub fn command(&self) -> &CM::Commands {
        &self.command
    }

    pub fn ret(&self, cpu: &CPU, value: GuestReg) {
        cpu.write_reg(get_exit_arch_regs()[ExitArgs::Ret], value)
            .unwrap();
    }

    #[must_use]
    pub fn ret_reg(&self) -> Regs {
        get_exit_arch_regs()[ExitArgs::Ret]
    }
}
