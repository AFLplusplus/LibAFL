//! Operating System specific abstractions
//!

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

#[cfg(any(unix, all(windows, feature = "std")))]
use crate::Error;

#[cfg(feature = "std")]
use std::{env, process::Command};

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

/// Core ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreId {
    /// The id of this core
    pub id: usize,
}

#[cfg(feature = "std")]
impl From<&CoreId> for core_affinity::CoreId {
    fn from(core_id: &CoreId) -> Self {
        core_affinity::CoreId { id: core_id.id }
    }
}

#[cfg(feature = "std")]
impl From<CoreId> for core_affinity::CoreId {
    fn from(core_id: CoreId) -> Self {
        core_affinity::CoreId { id: core_id.id }
    }
}

#[cfg(feature = "std")]
impl CoreId {
    /// Set the affinity of the current process to this [`CoreId`]
    pub fn set_affinity(&self) {
        core_affinity::set_for_current(self.into());
    }
}

impl From<usize> for CoreId {
    fn from(id: usize) -> Self {
        CoreId { id }
    }
}

#[cfg(feature = "std")]
impl From<&core_affinity::CoreId> for CoreId {
    fn from(core_id: &core_affinity::CoreId) -> Self {
        CoreId { id: core_id.id }
    }
}

#[cfg(feature = "std")]
impl From<core_affinity::CoreId> for CoreId {
    fn from(core_id: core_affinity::CoreId) -> Self {
        CoreId { id: core_id.id }
    }
}

/// A list of [`CoreId`] to use for fuzzing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cores {
    /// The original commandline used during parsing
    pub cmdline: String,

    /// Vec of core ids
    pub ids: Vec<CoreId>,
}

#[cfg(feature = "std")]
impl Cores {
    /// Pick all cores
    pub fn all() -> Result<Self, Error> {
        Self::from_cmdline("all")
    }

    /// Parses core binding args from user input.
    /// Returns a Vec of CPU IDs.
    /// * `./fuzzer --cores 1,2-4,6`: clients run in cores 1,2,3,4,6
    /// * `./fuzzer --cores all`: one client runs on each available core
    pub fn from_cmdline(args: &str) -> Result<Self, Error> {
        let mut cores: Vec<CoreId> = vec![];

        // ./fuzzer --cores all -> one client runs in each available core
        if args == "all" {
            let num_cores = if let Some(cores) = core_affinity::get_core_ids() {
                cores.len()
            } else {
                return Err(Error::IllegalState(
                    "Could not read core count from core_affinity".to_string(),
                ));
            };
            for x in 0..num_cores {
                cores.push(x.into());
            }
        } else {
            let core_args: Vec<&str> = args.split(',').collect();

            // ./fuzzer --cores 1,2-4,6 -> clients run in cores 1,2,3,4,6
            for csv in core_args {
                let core_range: Vec<&str> = csv.split('-').collect();
                if core_range.len() == 1 {
                    cores.push(core_range[0].parse::<usize>()?.into());
                } else if core_range.len() == 2 {
                    for x in core_range[0].parse::<usize>()?..=(core_range[1].parse::<usize>()?) {
                        cores.push(x.into());
                    }
                }
            }
        }

        if cores.is_empty() {
            return Err(Error::IllegalArgument(format!(
                "No cores specified! parsed: {}",
                args
            )));
        }

        Ok(Self {
            cmdline: args.to_string(),
            ids: cores,
        })
    }

    /// Checks if this [`Cores`] instance contains a given ``core_id``
    #[must_use]
    pub fn contains(&self, core_id: usize) -> bool {
        let core_id = CoreId::from(core_id);
        self.ids.contains(&core_id)
    }
}

impl From<&[usize]> for Cores {
    fn from(cores: &[usize]) -> Self {
        let cmdline = cores
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(",");
        let ids = cores.iter().map(|x| (*x).into()).collect();
        Self { cmdline, ids }
    }
}

impl From<Vec<usize>> for Cores {
    fn from(cores: Vec<usize>) -> Self {
        Self::from(cores.as_slice())
    }
}

#[cfg(feature = "std")]
impl TryFrom<&str> for Cores {
    type Error = Error;
    fn try_from(cores: &str) -> Result<Self, Self::Error> {
        Self::from_cmdline(cores)
    }
}

/// Parses core binding args from user input.
/// Returns a Vec of CPU IDs.
/// * `./fuzzer --cores 1,2-4,6`: clients run in cores 1,2,3,4,6
/// * `./fuzzer --cores all`: one client runs on each available core
#[must_use]
#[cfg(feature = "std")]
#[deprecated(since = "0.7.1", note = "Use Cores::from_cmdline instead")]
pub fn parse_core_bind_arg(args: &str) -> Option<Vec<usize>> {
    Cores::from_cmdline(args)
        .ok()
        .map(|cores| cores.ids.iter().map(|x| x.id).collect())
}
