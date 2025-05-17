use core::ffi::CStr;

use rustix::{
    fd::OwnedFd,
    fs::{Mode, OFlags, open},
    io::{Errno, read},
};
use thiserror::Error;

use crate::file::FileReader;

#[derive(Debug)]
pub struct LinuxFileReader {
    fd: OwnedFd,
}

impl FileReader for LinuxFileReader {
    type Error = LinuxFileReaderError;
    fn new(path: &'static CStr) -> Result<LinuxFileReader, Self::Error> {
        let fd = open(path, OFlags::RDONLY | OFlags::NONBLOCK, Mode::empty())
            .map_err(LinuxFileReaderError::FailedToOpen)?;

        Ok(LinuxFileReader { fd })
    }
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        read(&self.fd, buf).map_err(LinuxFileReaderError::FailedToRead)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum LinuxFileReaderError {
    #[error("Failed to open - errno: {0}")]
    FailedToOpen(Errno),
    #[error("Failed to read - errno: {0}")]
    FailedToRead(Errno),
}
