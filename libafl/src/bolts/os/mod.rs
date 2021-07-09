//! Operating System specific abstractions

#[cfg(any(unix, all(windows, feature = "std")))]
use crate::Error;

#[cfg(feature = "std")]
use std::{env, process::Command};

#[cfg(all(unix, feature = "std"))]
pub mod ashmem_server;

#[cfg(unix)]
pub mod unix_signals;

#[cfg(all(unix, feature = "std"))]
pub mod pipes;

#[cfg(all(unix, feature = "std"))]
use std::ffi::CString;

#[cfg(all(windows, feature = "std"))]
pub mod windows_exceptions;

#[cfg(unix)]
use libc::pid_t;

/// Child Process Handle
#[cfg(unix)]
pub struct ChildHandle {
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
            Err(Error::Unknown(format!("Fork failed ({})", pid)))
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
        -1 => Err(Error::File(std::io::Error::last_os_error())),
        _ => Ok(()),
    }
}

/// Parses core binding args from user input
/// Returns a Vec of CPU IDs.
/// `./fuzzer --cores 1,2-4,6` -> clients run in cores 1,2,3,4,6
/// ` ./fuzzer --cores all` -> one client runs on each available core
#[must_use]
#[cfg(feature = "std")]
pub fn parse_core_bind_arg(args: &str) -> Option<Vec<usize>> {
    let mut cores: Vec<usize> = vec![];
    if args == "all" {
        let num_cores = core_affinity::get_core_ids().unwrap().len();
        for x in 0..num_cores {
            cores.push(x);
        }
    } else {
        let core_args: Vec<&str> = args.split(',').collect();

        // ./fuzzer --cores 1,2-4,6 -> clients run in cores 1,2,3,4,6
        // ./fuzzer --cores all -> one client runs in each available core
        for csv in core_args {
            let core_range: Vec<&str> = csv.split('-').collect();
            if core_range.len() == 1 {
                cores.push(core_range[0].parse::<usize>().unwrap());
            } else if core_range.len() == 2 {
                for x in core_range[0].parse::<usize>().unwrap()
                    ..=(core_range[1].parse::<usize>().unwrap())
                {
                    cores.push(x);
                }
            }
        }
    }

    Some(cores)
}
