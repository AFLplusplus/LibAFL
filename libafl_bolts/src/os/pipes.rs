//! Unix `pipe` wrapper for `LibAFL`
#[cfg(feature = "std")]
use std::{
    borrow::Borrow,
    cell::RefCell,
    io::{self, ErrorKind, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::io::RawFd,
    },
    rc::Rc,
};

#[cfg(feature = "std")]
use nix::unistd::{pipe, read, write};

#[cfg(feature = "std")]
use crate::Error;

/// A unix pipe wrapper for `LibAFL`
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct Pipe {
    /// The read end of the pipe
    read_end: Option<Rc<RefCell<OwnedFd>>>,
    /// The write end of the pipe
    write_end: Option<Rc<RefCell<OwnedFd>>>,
}

#[cfg(feature = "std")]
impl Pipe {
    /// Create a new `Unix` pipe
    pub fn new() -> Result<Self, Error> {
        let (read_end, write_end) = pipe()?;
        Ok(Self {
            read_end: Some(Rc::new(RefCell::new(read_end))),
            write_end: Some(Rc::new(RefCell::new(write_end))),
        })
    }

    /// Close the read end of a pipe
    pub fn close_read_end(&mut self) {
        // `OwnedFd` closes on Drop
        self.read_end = None;
    }

    /// Close the write end of a pipe
    pub fn close_write_end(&mut self) {
        // `OwnedFd` closes on Drop
        self.write_end = None;
    }

    /// The read end
    #[must_use]
    pub fn read_end(&self) -> Option<RawFd> {
        self.read_end.as_ref().map(|fd| {
            let borrowed: &RefCell<OwnedFd> = fd.borrow();
            borrowed.borrow().as_raw_fd()
        })
    }

    /// The write end
    #[must_use]
    pub fn write_end(&self) -> Option<RawFd> {
        self.write_end.as_ref().map(|fd| {
            let borrowed: &RefCell<OwnedFd> = fd.borrow();
            borrowed.borrow().as_raw_fd()
        })
    }
}

#[cfg(feature = "std")]
impl Read for Pipe {
    /// Reads a few bytes
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.read_end() {
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
        match self.write_end.as_ref() {
            Some(write_end) => {
                let borrowed: &RefCell<OwnedFd> = write_end;
                match write((*borrowed).borrow().as_fd(), buf) {
                    Ok(res) => Ok(res),
                    Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
                }
            }
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
