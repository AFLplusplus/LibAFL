use std::{
    fmt::{Display, Formatter},
    rc::Rc,
};

use enum_map::Enum;
use libafl::state::{HasExecutions, State};

use crate::{
    command::{CommandManager, IsCommand},
    get_exit_arch_regs, EmulatorExitHandler, EmulatorToolTuple, GuestReg, Regs, CPU,
};

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
pub struct SyncExit<CM, EH, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    QT: EmulatorToolTuple<S>,
    S: Unpin + State + HasExecutions,
{
    command: Rc<dyn IsCommand<CM, EH, QT, S>>,
}

impl<CM, EH, QT, S> SyncExit<CM, EH, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    QT: EmulatorToolTuple<S>,
    S: Unpin + State + HasExecutions,
{
    #[must_use]
    pub fn new(command: Rc<dyn IsCommand<CM, EH, QT, S>>) -> Self {
        Self { command }
    }

    #[must_use]
    pub fn command(&self) -> Rc<dyn IsCommand<CM, EH, QT, S>> {
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

impl<CM, EH, QT, S> Display for SyncExit<CM, EH, QT, S>
where
    CM: CommandManager<EH, QT, S>,
    EH: EmulatorExitHandler<QT, S>,
    QT: EmulatorToolTuple<S>,
    S: Unpin + State + HasExecutions,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command)
    }
}
