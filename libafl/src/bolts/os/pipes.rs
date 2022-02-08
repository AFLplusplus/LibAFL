//! Unix `pipe` wrapper for `LibAFL`
use crate::Error;
#[cfg(feature = "std")]
use nix::unistd::{close, pipe, read, write};
#[cfg(feature = "std")]
use std::{
    io::{self, ErrorKind, Read, Write},
    os::unix::io::RawFd,
};

/// A unix pipe wrapper for `LibAFL`
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct Pipe {
    /// The read end of the pipe
    read_end: Option<RawFd>,
    /// The write end of the pipe
    write_end: Option<RawFd>,
}

#[cfg(feature = "std")]
impl Pipe {
    /// Create a new `Unix` pipe
    pub fn new() -> Result<Self, Error> {
        let (read_end, write_end) = pipe()?;
        Ok(Self {
            read_end: Some(read_end),
            write_end: Some(write_end),
        })
    }

    /// Close the read end of a pipe
    pub fn close_read_end(&mut self) {
        if let Some(read_end) = self.read_end {
            let _ = close(read_end);
            self.read_end = None;
        }
    }

    /// Close the write end of a pipe
    pub fn close_write_end(&mut self) {
        if let Some(write_end) = self.write_end {
            let _ = close(write_end);
            self.write_end = None;
        }
    }

    /// The read end
    #[must_use]
    pub fn read_end(&self) -> Option<RawFd> {
        self.read_end
    }

    /// The write end
    #[must_use]
    pub fn write_end(&self) -> Option<RawFd> {
        self.write_end
    }
}

#[cfg(feature = "std")]
impl Read for Pipe {
    /// Reads a few bytes
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.read_end {
            Some(read_end) => match read(read_end, buf) {
                Ok(res) => Ok(res),
                Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
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
                Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
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

#[cfg(feature = "std")]
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
