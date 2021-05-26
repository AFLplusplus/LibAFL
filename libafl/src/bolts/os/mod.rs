//! Operating System specific abstractions

use alloc::vec::Vec;

#[cfg(any(unix, all(windows, feature = "std")))]
use crate::Error;

#[cfg(feature = "std")]
use std::{env, process::Command};

#[cfg(all(unix, feature = "std"))]
pub mod ashmem_server;

#[cfg(unix)]
pub mod unix_signals;

#[cfg(unix)]
pub mod pipes;

#[cfg(all(unix, feature = "std"))]
use std::ffi::CString;

#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
use std::fs::File;

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

/// Allows one to walk the mappings in /proc/self/maps, caling a callback function for each
/// mapping.
/// If the callback returns true, we stop the walk.
#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
pub fn walk_self_maps(visitor: &mut dyn FnMut(usize, usize, String, String) -> bool) {
    use regex::Regex;
    use std::io::{BufRead, BufReader};
    let re = Regex::new(r"^(?P<start>[0-9a-f]{8,16})-(?P<end>[0-9a-f]{8,16}) (?P<perm>[-rwxp]{4}) (?P<offset>[0-9a-f]{8}) [0-9a-f]+:[0-9a-f]+ [0-9]+\s+(?P<path>.*)$")
        .unwrap();

    let mapsfile = File::open("/proc/self/maps").expect("Unable to open /proc/self/maps");

    for line in BufReader::new(mapsfile).lines() {
        let line = line.unwrap();
        if let Some(caps) = re.captures(&line) {
            if visitor(
                usize::from_str_radix(caps.name("start").unwrap().as_str(), 16).unwrap(),
                usize::from_str_radix(caps.name("end").unwrap().as_str(), 16).unwrap(),
                caps.name("perm").unwrap().as_str().to_string(),
                caps.name("path").unwrap().as_str().to_string(),
            ) {
                break;
            };
        }
    }
}

/// Get the start and end address, permissions and path of the mapping containing a particular address
#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
pub fn find_mapping_for_address(address: usize) -> Result<(usize, usize, String, String), Error> {
    let mut result = (0, 0, "".to_string(), "".to_string());
    walk_self_maps(&mut |start, end, permissions, path| {
        if start <= address && address < end {
            result = (start, end, permissions, path);
            true
        } else {
            false
        }
    });

    if result.0 == 0 {
        Err(Error::Unknown(
            "Couldn't find a mapping for this address".to_string(),
        ))
    } else {
        Ok(result)
    }
}

/// Get the start and end address of the mapping containing with a particular path
#[cfg(all(feature = "std", any(target_os = "linux", target_os = "android")))]
#[must_use]
pub fn find_mapping_for_path(libpath: &str) -> (usize, usize) {
    let mut libstart = 0;
    let mut libend = 0;
    walk_self_maps(&mut |start, end, _permissions, path| {
        if libpath == path {
            if libstart == 0 {
                libstart = start;
            }

            libend = end;
        }
        false
    });

    (libstart, libend)
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
