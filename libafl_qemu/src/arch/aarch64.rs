use std::sync::OnceLock;

use capstone::arch::BuildsCapstone;
use enum_map::{EnumMap, enum_map};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::aarch64::*;

use crate::{CallingConvention, GuestAddr, QemuRWError, QemuRWErrorKind, sync_exit::ExitArgs};

#[expect(non_upper_case_globals)]
impl CallingConvention {
    pub const Default: CallingConvention = CallingConvention::Aapcs64;
}

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,
    X30 = 30,
    Sp = 31,
    Pc = 32,
    Pstate = 33,
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::X0,
            ExitArgs::Cmd  => Regs::X0,
            ExitArgs::Arg1 => Regs::X1,
            ExitArgs::Arg2 => Regs::X2,
            ExitArgs::Arg3 => Regs::X3,
            ExitArgs::Arg4 => Regs::X4,
            ExitArgs::Arg5 => Regs::X5,
            ExitArgs::Arg6 => Regs::X6,
        }
    })
}

/// alias registers
#[expect(non_upper_case_globals)]
impl Regs {
    pub const Fp: Regs = Regs::X29;
    pub const Lr: Regs = Regs::X30;
}

/// Return an ARM64 ArchCapstoneBuilder
pub fn capstone() -> capstone::arch::arm64::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
}

pub type GuestReg = u64;

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
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::Aapcs64, conv)?;

        match idx {
            0 => self.read_reg(Regs::X0),
            1 => self.read_reg(Regs::X1),
            2 => self.read_reg(Regs::X2),
            3 => self.read_reg(Regs::X3),
            4 => self.read_reg(Regs::X4),
            5 => self.read_reg(Regs::X5),
            6 => self.read_reg(Regs::X6),
            7 => self.read_reg(Regs::X7),
            _ => {
                const SIZE: usize = size_of::<GuestReg>();
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                /*
                 * Stack is full and descending. SP points to return address, arguments
                 * are in reverse order above that. 8th argument is at SP + 8.
                 */

                let offset = (SIZE as GuestAddr) * (GuestAddr::from(idx) - 7);
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
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::Aapcs64, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::X0, val),
            1 => self.write_reg(Regs::X1, val),
            2 => self.write_reg(Regs::X2, val),
            3 => self.write_reg(Regs::X3, val),
            4 => self.write_reg(Regs::X4, val),
            5 => self.write_reg(Regs::X5, val),
            6 => self.write_reg(Regs::X6, val),
            7 => self.write_reg(Regs::X7, val),
            _ => {
                let val: GuestReg = val.into();
                let stack_ptr: GuestAddr = self.read_reg(Regs::Sp)?;
                /*
                 * Stack is full and descending. SP points to return address, arguments
                 * are in reverse order above that. 8th argument is at SP + 8.
                 */
                let size: GuestAddr = size_of::<GuestReg>() as GuestAddr;
                let offset = size * (GuestAddr::from(idx) - 7);
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
