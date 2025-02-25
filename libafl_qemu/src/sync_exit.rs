use std::fmt::Debug;

use enum_map::Enum;

use crate::{CPU, GuestReg, Regs, get_exit_arch_regs};

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
pub struct CustomInsn<C> {
    command: C,
}

impl<C> CustomInsn<C> {
    #[must_use]
    pub fn new(command: C) -> Self {
        Self { command }
    }

    #[must_use]
    pub fn command(&self) -> &C {
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
