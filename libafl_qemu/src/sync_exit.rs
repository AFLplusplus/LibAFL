use std::fmt::{Display, Formatter};

use enum_map::Enum;

use crate::{command::Command, get_exit_arch_regs, GuestReg, Regs, CPU};

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

#[derive(Debug, Clone)]
pub struct SyncExit {
    command: Command,
}

impl SyncExit {
    #[must_use]
    pub fn new(command: Command) -> Self {
        Self { command }
    }

    #[must_use]
    pub fn command(&self) -> &Command {
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

impl Display for SyncExit {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command)
    }
}
