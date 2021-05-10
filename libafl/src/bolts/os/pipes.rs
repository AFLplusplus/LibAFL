//! Unix `pipe` wrapper for `LibAFL`
use crate::Error;
use nix::unistd::{close, pipe};

#[cfg(feature = "std")]
use nix::unistd::{read, write};
#[cfg(feature = "std")]
use std::{
    io::{self, ErrorKind, Read, Write},
    os::unix::io::RawFd,
};

#[cfg(not(feature = "std"))]
type RawFd = i32;

#[derive(Debug, Clone)]
pub struct Pipe {
    read_end: Option<RawFd>,
    write_end: Option<RawFd>,
}

impl Pipe {
    pub fn new() -> Result<Self, Error> {
        let (read_end, write_end) = pipe()?;
        Ok(Self {
            read_end: Some(read_end),
            write_end: Some(write_end),
        })
    }

    pub fn close_read_end(&mut self) {
        if let Some(read_end) = self.read_end {
            let _ = close(read_end);
            self.read_end = None;
        }
    }

    pub fn close_write_end(&mut self) {
        if let Some(write_end) = self.write_end {
            let _ = close(write_end);
            self.write_end = None;
        }
    }
}

#[cfg(feature = "std")]
impl Read for Pipe {
    /// Reads a few bytes
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.read_end {
            Some(read_end) => match read(read_end, buf) {
                Ok(res) => Ok(res),
                Err(e) => Err(io::Error::from_raw_os_error(e.as_errno().unwrap() as i32)),
            },
            None => Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "Read pipe end was already closed",
            )),
        }
    }
}

#[cfg(feature = "std")]
impl Write for Pipe {
    /// Writes a few bytes
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self.write_end {
            Some(write_end) => match write(write_end, buf) {
                Ok(res) => Ok(res),
                Err(e) => Err(io::Error::from_raw_os_error(e.as_errno().unwrap() as i32)),
            },
            None => Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "Write pipe end was already closed",
            )),
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        if let Some(read_end) = self.read_end {
            let _ = close(read_end);
        }
        if let Some(write_end) = self.write_end {
            let _ = close(write_end);
        }
    }
}
