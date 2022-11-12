//! Operating System specific abstractions
//!

#[cfg(feature = "std")]
use std::{env, process::Command};

#[cfg(any(unix, all(windows, feature = "std")))]
use crate::Error;

#[cfg(all(unix, feature = "std"))]
pub mod unix_shmem_server;

#[cfg(unix)]
pub mod unix_signals;

#[cfg(all(unix, feature = "std"))]
pub mod pipes;

#[cfg(all(unix, feature = "std"))]
use std::ffi::CString;

// Allow a few extra features we need for the whole module
#[cfg(all(windows, feature = "std"))]
#[allow(missing_docs, overflowing_literals)]
pub mod windows_exceptions;

#[cfg(unix)]
use libc::pid_t;

/// Child Process Handle
#[cfg(unix)]
#[derive(Debug)]
pub struct ChildHandle {
    /// The process id
    pub pid: pid_t,
}

#[cfg(unix)]
impl ChildHandle {
    /// Block until the child exited and the status code becomes available
    #[must_use]
    pub fn status(&self) -> i32 {
        let mut status = -1;
        unsafe {
            libc::waitpid(self.pid, &mut status, 0);
        }
        status
    }
}

/// The `ForkResult` (result of a fork)
#[cfg(unix)]
#[derive(Debug)]
pub enum ForkResult {
    /// The fork finished, we are the parent process.
    /// The child has the handle `ChildHandle`.
    Parent(ChildHandle),
    /// The fork finished, we are the child process.
    Child,
}

/// Unix has forks.
/// # Safety
/// A Normal fork. Runs on in two processes. Should be memory safe in general.
#[cfg(unix)]
pub unsafe fn fork() -> Result<ForkResult, Error> {
    match libc::fork() {
        pid if pid > 0 => Ok(ForkResult::Parent(ChildHandle { pid })),
        pid if pid < 0 => {
            // Getting errno from rust is hard, we'll just let the libc print to stderr for now.
            // In any case, this should usually not happen.
            #[cfg(feature = "std")]
            {
                let err_str = CString::new("Fork failed").unwrap();
                libc::perror(err_str.as_ptr());
            }
            Err(Error::unknown(format!("Fork failed ({pid})")))
        }
        _ => Ok(ForkResult::Child),
    }
}

/// Executes the current process from the beginning, as subprocess.
/// use `start_self.status()?` to wait for the child
#[cfg(feature = "std")]
pub fn startable_self() -> Result<Command, Error> {
    let mut startable = Command::new(env::current_exe()?);
    startable
        .current_dir(env::current_dir()?)
        .args(env::args().skip(1));
    Ok(startable)
}

/// "Safe" wrapper around dup2
#[cfg(all(unix, feature = "std"))]
pub fn dup2(fd: i32, device: i32) -> Result<(), Error> {
    match unsafe { libc::dup2(fd, device) } {
        -1 => Err(Error::file(std::io::Error::last_os_error())),
        _ => Ok(()),
    }
}
