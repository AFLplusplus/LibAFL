#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::Error;

use anyhow::{Result, anyhow};
use libc::_exit;
#[cfg(any(target_os = "linux", target_os = "android"))]
use libc::{PR_SET_PDEATHSIG, prctl};
#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::signal::SIGKILL;
use nix::{
    sys::{
        signal::{SIGCHLD, SaFlags, SigAction, SigHandler, SigSet, sigaction},
        wait::{WaitStatus::Exited, waitpid},
    },
    unistd::Pid,
};

pub struct Exit;

impl Exit {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn die_on_parent_exit() -> Result<()> {
        if unsafe { prctl(PR_SET_PDEATHSIG, SIGKILL) } != 0 {
            Err(anyhow!(
                "Failed to prctl(PR_SET_PDEATHSIG): {:?}",
                Error::last_os_error()
            ))?;
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub fn die_on_parent_exit() -> Result<()> {
        panic!("Only supported for Linux and Android");
    }

    pub fn die_on_child_exit() -> Result<()> {
        let sig_action = SigAction::new(
            SigHandler::Handler(Self::handle_sigchld),
            SaFlags::empty(),
            SigSet::empty(),
        );

        unsafe { sigaction(SIGCHLD, &sig_action) }
            .map_err(|e| anyhow!("Failed to sigaction: {e:}"))?;
        Ok(())
    }

    extern "C" fn handle_sigchld(sig: libc::c_int) {
        info!("handle_sigchld: {sig:}");
        let status = waitpid(Pid::from_raw(-1), None).expect("Failed to wait for child");
        match status {
            Exited(pid, exit) => {
                info!("Exited: {pid:}");
                unsafe { _exit(exit) };
            }
            _ => {
                panic!("Invalid exit status: {status:#?}");
            }
        }
    }

    pub fn wait_for_child() -> Result<()> {
        let status =
            waitpid(Pid::from_raw(-1), None).map_err(|e| anyhow!("Failed to waitpid: {e:}"))?;
        info!("STATUS: {status:#?}");
        Ok(())
    }
}
