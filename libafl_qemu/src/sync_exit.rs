use std::{
    fmt::{Display, Formatter},
    rc::Rc,
};

use enum_map::Enum;
use libafl::inputs::UsesInput;

use crate::{command::IsCommand, get_exit_arch_regs, GuestReg, Regs, CPU};

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

#[derive(Debug)]
pub struct SyncExit<CM, EH, ET, S>
where
    S: UsesInput,
{
    command: Rc<dyn IsCommand<CM, EH, ET, S>>,
}

impl<CM, EH, ET, S> SyncExit<CM, EH, ET, S>
where
    S: UsesInput,
{
    #[must_use]
    pub fn new(command: Rc<dyn IsCommand<CM, EH, ET, S>>) -> Self {
        Self { command }
    }

    #[must_use]
    pub fn command(&self) -> Rc<dyn IsCommand<CM, EH, ET, S>> {
        self.command.clone()
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

impl<CM, EH, ET, S> Display for SyncExit<CM, EH, ET, S>
where
    S: UsesInput,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command)
    }
}
