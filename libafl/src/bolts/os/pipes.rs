use nix::unistd::{close, pipe, read, write};

#[derive(Debug, Clone)]
pub struct Pipe {
    read_end: Option<RawFd>,
    write_end: Option<RawFd>,
}

impl Pipe {
    fn new() -> Self {
        let mut fds = [-1 as c_int, -1 as c_int];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret < 0 {
            panic!("pipe() failed");
        }
        Self {
            read_end: fds[0],
            write_end: fds[1],
        }
    }

    fn close_read_end() {
        if let Some(read_end) = self.read_end {
            close(read_end);
            self.read_end = None;
        }
    }

    fn close_write_end() {
        if let Some(write_end) = self.write_end {
            close(write_end);
            self.write_end = None;
        }
    }
}

impl Read for Pipe {
    /// Reads a few bytes
    fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        match self.read_end {
            Some(read_end) => Ok(read(self.read_end, buf)?),
            None => Err(Error::IllegalState("Read pipe was already closed")),
        }
    }
}

impl Write for Pipe {
    /// Writes a few bytes
    fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        match self.read_end {
            Some(read_end) => Ok(write(self.write_end, buf)?),
            None => Err(Error::IllegalState("Write pipe was already closed")),
        }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        if let Some(read_end) = self.read_end {
            let _ = close(self.read_end);
        }
        if let Some(write_end) = self.write_end {
            let _ = close(self.write_end);
        }
    }
}
