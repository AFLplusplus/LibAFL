use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
};

use anyhow::{Result, anyhow};
use nix::unistd::{dup2, execvp};

use crate::{args::ChildArgs, exit::Exit};

pub struct Child {
    argv: Vec<String>,
    fd1: OwnedFd,
    fd2: OwnedFd,
}

impl Child {
    fn launch(&self) -> Result<()> {
        let cargs = self
            .argv
            .iter()
            .map(|x| CString::new(x.clone()).map_err(|e| anyhow!("Failed to read argument: {e:}")))
            .collect::<Result<Vec<CString>>>()?;

        info!("cargs: {cargs:#?}");

        execvp(&cargs[0], &cargs).map_err(|e| anyhow!("Failed to exceve: {e:}"))?;
        unreachable!("Should never get here!");
    }

    /// # Safety
    /// Should be only called once. Will dup the stdout and stderr fds.
    unsafe fn redirect(&self) -> Result<()> {
        // # Safety
        // Nothing should have happened before we call this. Stdout should be a valid fd.
        let mut stdout = unsafe { OwnedFd::from_raw_fd(std::io::stdout().as_raw_fd()) };
        // # Safety
        // Nothing should have happened before we call this. Stderr should be a valid fd.
        let mut stderr = unsafe { OwnedFd::from_raw_fd(std::io::stderr().as_raw_fd()) };
        dup2(&self.fd1, &mut stdout).map_err(|e| anyhow!("Failed to redirect stdout: {e:}"))?;

        dup2(&self.fd2, &mut stderr).map_err(|e| anyhow!("Failed to redirect stderr: {e:}"))?;
        // Make sure the fds don't get dropped/closed.
        let _ = stdout.into_raw_fd();
        let _ = stderr.into_raw_fd();
        Ok(())
    }

    /// # Safety
    /// The will redirect stdout and stderr.
    /// Make sure `fd1` and `fd2` are valid file descriptors to redirect to, and stdout/err hasn't been closed.
    pub unsafe fn run(self) -> Result<()> {
        Exit::die_on_parent_exit()?;
        // # Safety
        // The will redirect stdout and stderr.
        unsafe {
            self.redirect()?;
        }
        self.launch()?;

        Ok(())
    }

    pub fn new(args: &impl ChildArgs, fd1: OwnedFd, fd2: OwnedFd) -> Child {
        Child {
            argv: args.argv().to_vec(),
            fd1,
            fd2,
        }
    }
}
