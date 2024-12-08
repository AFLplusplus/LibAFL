use core::fmt;
use std::{convert::Infallible, fmt::Display};

use libafl_qemu_sys::{CPUStatePtr, GuestAddr};

use crate::{config::QemuConfigBuilderError, CallingConvention};

#[derive(Debug)]
pub enum QemuError {
    Init(QemuInitError),
    Exit(QemuExitError),
    RW(QemuRWError),
}

#[derive(Debug)]
pub enum QemuInitError {
    MultipleInstances,
    EmptyArgs,
    ConfigurationError(QemuConfigBuilderError),
    Infallible,
    TooManyArgs(usize),
}

impl From<Infallible> for QemuInitError {
    fn from(_: Infallible) -> Self {
        QemuInitError::Infallible
    }
}

#[derive(Debug, Clone)]
pub enum QemuExitError {
    UnknownKind, // Exit reason was not NULL, but exit kind is unknown. Should never happen.
    UnexpectedExit, // Qemu exited without going through an expected exit point. Can be caused by a crash for example.
}

#[derive(Debug, Clone)]
pub enum QemuRWErrorKind {
    Read,
    Write,
}

#[derive(Debug, Clone)]
pub enum QemuRWErrorCause {
    WrongCallingConvention(CallingConvention, CallingConvention), // expected, given
    WrongArgument(i32),
    CurrentCpuNotFound,
    Reg(i32),
    WrongMemoryLocation(GuestAddr, usize), // addr, size
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
            QemuInitError::EmptyArgs => {
                write!(f, "QEMU emulator args cannot be empty")
            }
            QemuInitError::ConfigurationError(config_error) => {
                write!(f, "QEMU Configuration error: {config_error}")
            }
            QemuInitError::TooManyArgs(n) => {
                write!(
                    f,
                    "Too many arguments passed to QEMU emulator ({n} > i32::MAX)"
                )
            }
            QemuInitError::Infallible => {
                write!(f, "Infallible error, should never be reached.")
            }
        }
    }
}

impl From<QemuInitError> for libafl::Error {
    fn from(err: QemuInitError) -> Self {
        libafl::Error::runtime(format!("QEMU Init error: {err}"))
    }
}

impl From<QemuRWError> for libafl::Error {
    fn from(err: QemuRWError) -> Self {
        libafl::Error::runtime(format!("QEMU Runtime error: {err:?}"))
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
    pub fn new_argument_error(kind: QemuRWErrorKind, reg_id: i32) -> Self {
        Self::new(kind, QemuRWErrorCause::WrongArgument(reg_id), None)
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
