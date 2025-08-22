use rustix::{
    fd::OwnedFd,
    fs::{Mode, OFlags, open},
    io::{Errno, read},
};
use thiserror::Error;

use crate::maps::MapReader;

#[derive(Debug)]
pub struct LinuxMapReader {
    fd: OwnedFd,
}

impl MapReader for LinuxMapReader {
    type Error = LinuxMapReaderError;

    fn new() -> Result<LinuxMapReader, LinuxMapReaderError> {
        let fd = open(
            c"/proc/self/maps",
            OFlags::RDONLY | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(LinuxMapReaderError::FailedToOpen)?;
        Ok(LinuxMapReader { fd })
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        read(&self.fd, buf).map_err(LinuxMapReaderError::FailedToRead)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum LinuxMapReaderError {
    #[error("Failed to read - errno: {0}")]
    FailedToRead(Errno),
    #[error("Failed to open - errno: {0}")]
    FailedToOpen(Errno),
}
