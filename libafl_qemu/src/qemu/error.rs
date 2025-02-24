use core::fmt;
use std::{convert::Infallible, fmt::Display};

use libafl_qemu_sys::{CPUStatePtr, GuestAddr};

use crate::CallingConvention;

#[derive(Clone, Debug)]
pub enum QemuError {
    Init(QemuInitError),
    Exit(QemuExitError),
    RW(QemuRWError),
}

#[derive(Clone, Debug)]
pub enum QemuInitError {
    MultipleInstances,
    NoParametersProvided,
    EmptyArgs,
    Infallible,
    TooManyArgs(usize),
}

#[derive(Clone, Debug)]
pub enum QemuExitError {
    UnknownKind, // Exit reason was not NULL, but exit kind is unknown. Should never happen.
    UnexpectedExit, // Qemu exited without going through an expected exit point. Can be caused by a crash for example.
}

#[derive(Clone, Debug)]
pub enum QemuRWErrorKind {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub enum QemuRWErrorCause {
    WrongCallingConvention(CallingConvention, CallingConvention), // expected, given
    WrongArgument(u8),
    CurrentCpuNotFound,
    Reg(i32),
    WrongMemoryLocation(GuestAddr, usize), // addr, size
}

#[derive(Clone, Debug)]
#[expect(dead_code)]
pub struct QemuRWError {
    kind: QemuRWErrorKind,
    cause: QemuRWErrorCause,
    cpu: Option<CPUStatePtr>, // Only makes sense when cause != CurrentCpuNotFound
}

impl std::error::Error for QemuInitError {}

impl Display for QemuInitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QemuInitError::MultipleInstances => {
                write!(f, "Only one instance of the QEMU Emulator is permitted")
            }
            QemuInitError::NoParametersProvided => {
                write!(f, "No parameters were provided to initialize QEMU.")
            }
            QemuInitError::EmptyArgs => {
                write!(f, "QEMU emulator args cannot be empty")
            }
            QemuInitError::TooManyArgs(n) => {
                write!(
                    f,
                    "Too many arguments passed to QEMU emulator ({n} > i32::MAX)"
                )
            }
            QemuInitError::Infallible => {
                panic!("Infallible error, should never be reached.")
            }
        }
    }
}

impl From<QemuInitError> for libafl::Error {
    fn from(err: QemuInitError) -> Self {
        libafl::Error::unknown(format!("{err}"))
    }
}

impl From<Infallible> for QemuInitError {
    fn from(_: Infallible) -> Self {
        QemuInitError::Infallible
    }
}

impl QemuRWError {
    #[must_use]
    pub fn new(kind: QemuRWErrorKind, cause: QemuRWErrorCause, cpu: Option<CPUStatePtr>) -> Self {
        Self { kind, cause, cpu }
    }

    pub fn wrong_reg<R>(kind: QemuRWErrorKind, reg: R, cpu: Option<CPUStatePtr>) -> Self
    where
        R: Into<i32> + Clone,
    {
        Self::new(kind, QemuRWErrorCause::Reg(reg.into()), cpu)
    }

    pub fn wrong_mem_location(
        kind: QemuRWErrorKind,
        cpu: CPUStatePtr,
        addr: GuestAddr,
        size: usize,
    ) -> Self {
        Self::new(
            kind,
            QemuRWErrorCause::WrongMemoryLocation(addr, size),
            Some(cpu),
        )
    }

    #[must_use]
    pub fn current_cpu_not_found(kind: QemuRWErrorKind) -> Self {
        Self::new(kind, QemuRWErrorCause::CurrentCpuNotFound, None)
    }

    #[must_use]
    pub fn new_argument_error(kind: QemuRWErrorKind, arg_id: u8) -> Self {
        Self::new(kind, QemuRWErrorCause::WrongArgument(arg_id), None)
    }

    pub fn check_conv(
        kind: QemuRWErrorKind,
        expected_conv: CallingConvention,
        given_conv: CallingConvention,
    ) -> Result<(), Self> {
        if expected_conv != given_conv {
            return Err(Self::new(
                kind,
                QemuRWErrorCause::WrongCallingConvention(expected_conv, given_conv),
                None,
            ));
        }

        Ok(())
    }
}

impl From<QemuRWError> for QemuError {
    fn from(qemu_rw_error: QemuRWError) -> Self {
        QemuError::RW(qemu_rw_error)
    }
}

impl From<QemuError> for libafl::Error {
    fn from(qemu_error: QemuError) -> Self {
        libafl::Error::runtime(qemu_error)
    }
}

impl From<QemuError> for String {
    fn from(qemu_error: QemuError) -> Self {
        format!("LibAFL QEMU Error: {qemu_error:?}")
    }
}
