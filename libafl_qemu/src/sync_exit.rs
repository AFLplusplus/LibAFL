use std::{
    fmt::{Display, Formatter},
    rc::Rc,
};

use enum_map::Enum;
use libafl::state::{HasExecutions, State};

use crate::{
    command::{CommandManager, IsCommand},
    get_exit_arch_regs, EmulatorExitHandler, GuestReg, QemuHelperTuple, Regs, CPU,
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
pub struct SyncExit<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    command: Rc<dyn IsCommand<CM, E, QT, S>>,
}

impl<CM, E, QT, S> SyncExit<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    #[must_use]
    pub fn new(command: Rc<dyn IsCommand<CM, E, QT, S>>) -> Self {
        Self { command }
    }

    #[must_use]
    pub fn command(&self) -> Rc<dyn IsCommand<CM, E, QT, S>> {
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

impl<CM, E, QT, S> Display for SyncExit<CM, E, QT, S>
where
    CM: CommandManager<E, QT, S>,
    E: EmulatorExitHandler<QT, S>,
    QT: QemuHelperTuple<S>,
    S: State + HasExecutions,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.command)
    }
}
