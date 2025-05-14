use std::{
    ffi::CString,
    os::fd::{AsRawFd, RawFd},
};

use anyhow::{anyhow, Result};
use nix::unistd::{dup2, execvp};

use crate::{args::ChildArgs, exit::Exit};

pub struct Child {
    argv: Vec<String>,
    fd1: RawFd,
    fd2: RawFd,
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
        Ok(())
    }

    fn redirect(&self) -> Result<()> {
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        dup2(self.fd1, stdout.as_raw_fd())
            .map_err(|e| anyhow!("Failed to redirect stdout: {e:}"))?;

        dup2(self.fd2, stderr.as_raw_fd())
            .map_err(|e| anyhow!("Failed to redirect stderr: {e:}"))?;
        Ok(())
    }

    pub fn run(&self) -> Result<()> {
        Exit::die_on_parent_exit()?;
        self.redirect()?;
        self.launch()?;

        Ok(())
    }

    pub fn new(args: &impl ChildArgs, fd1: RawFd, fd2: RawFd) -> Child {
        Child {
            argv: args.argv().to_vec(),
            fd1,
            fd2,
        }
    }
}
