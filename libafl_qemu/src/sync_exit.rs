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

#[derive(Clone, Debug)]
pub struct SyncExit<CM, S>
where
    CM: CommandManager<S>,
    S: UsesInput,
{
    command: CM::Commands,
}

impl<CM, S> SyncExit<CM, S>
where
    CM: CommandManager<S>,
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
