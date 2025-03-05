use std::sync::OnceLock;

use capstone::arch::BuildsCapstone;
use enum_map::{EnumMap, enum_map};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::arm::*;

use crate::{CallingConvention, GuestAddr, QemuRWError, QemuRWErrorKind, sync_exit::ExitArgs};

#[expect(non_upper_case_globals)]
impl CallingConvention {
    pub const Default: CallingConvention = CallingConvention::Aapcs;
}

/// Registers for the ARM instruction set.
#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
    R25 = 25,
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::R0,
            ExitArgs::Cmd  => Regs::R0,
            ExitArgs::Arg1 => Regs::R1,
            ExitArgs::Arg2 => Regs::R2,
            ExitArgs::Arg3 => Regs::R3,
            ExitArgs::Arg4 => Regs::R4,
            ExitArgs::Arg5 => Regs::R5,
            ExitArgs::Arg6 => Regs::R6,
        }
    })
}

/// alias registers
#[expect(non_upper_case_globals)]
impl Regs {
    pub const Sp: Regs = Regs::R13;
    pub const Lr: Regs = Regs::R14;
    pub const Pc: Regs = Regs::R15;
    pub const Sb: Regs = Regs::R9;
    pub const Sl: Regs = Regs::R10;
    pub const Fp: Regs = Regs::R11;
    pub const Ip: Regs = Regs::R12;
    pub const Cpsr: Regs = Regs::R25;
}

/// Return an ARM ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::arm::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Arm)
}

/// Return an ARM Thumb ArchCapstoneBuilder
pub fn capstone_thumb() -> capstone::arch::arm::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Thumb)
}

pub type GuestReg = u32;

impl crate::ArchExtras for crate::CPU {
    fn read_return_address(&self) -> Result<GuestReg, QemuRWError> {
        self.read_reg(Regs::Lr)
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.write_reg(Regs::Lr, val)
    }

    fn read_function_argument_with_cc(
        &self,
        idx: u8,
        conv: CallingConvention,
    ) -> Result<GuestReg, QemuRWError> {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::Aapcs, conv)?;

        match idx {
            0 => self.read_reg(Regs::R0),
            1 => self.read_reg(Regs::R1),
            2 => self.read_reg(Regs::R2),
            3 => self.read_reg(Regs::R3),
            _ => {
                const SIZE: usize = size_of::<GuestReg>();
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                /*
                 * Stack is full and descending. SP points to return address, arguments
                 * are in reverse order above that. 4th argument is at SP + 8.
                 */

                let offset = (SIZE as GuestAddr) * (GuestAddr::from(idx) - 3);
                let mut buf = [0; SIZE];
                self.read_mem(stack_ptr + offset, &mut buf)?;

                #[cfg(feature = "be")]
                {
                    Ok(GuestReg::from_le_bytes(buf).into())
                }
                #[cfg(not(feature = "be"))]
                Ok(GuestReg::from_le_bytes(buf).into())
            }
        }
    }

    fn write_function_argument_with_cc<T>(
        &self,
        idx: u8,
        val: T,
        conv: CallingConvention,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::Aapcs, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::R0, val),
            1 => self.write_reg(Regs::R1, val),
            2 => self.write_reg(Regs::R2, val),
            3 => self.write_reg(Regs::R3, val),
            _ => {
                let val: GuestReg = val.into();
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                /*
                 * Stack is full and descending. SP points to return address, arguments
                 * are in reverse order above that. 4th argument is at SP + 4.
                 */
                let size: GuestAddr = size_of::<GuestReg>() as GuestAddr;
                let offset = size * (GuestAddr::from(idx) - 3);

                #[cfg(feature = "be")]
                let arg = val.to_be_bytes();

                #[cfg(not(feature = "be"))]
                let arg = val.to_le_bytes();

                self.write_mem(stack_ptr + offset, &arg)?;

                Ok(())
            }
        }
    }
}
