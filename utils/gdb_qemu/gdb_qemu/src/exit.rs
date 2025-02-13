use anyhow::{anyhow, Result};
use libc::{_exit, prctl, PR_SET_PDEATHSIG};
use nix::{
    sys::{
        signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, SIGCHLD, SIGKILL},
        wait::{waitpid, WaitStatus::Exited},
    },
    unistd::Pid,
};

use crate::errno::errno;

pub struct Exit;

impl Exit {
    pub fn die_on_parent_exit() -> Result<()> {
        if unsafe { prctl(PR_SET_PDEATHSIG, SIGKILL) } != 0 {
            Err(anyhow!("Failed to prctl(PR_SET_PDEATHSIG): {}", errno()))?;
        }
        Ok(())
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
