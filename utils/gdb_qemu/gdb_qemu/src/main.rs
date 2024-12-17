mod args;
mod child;
mod errno;
mod exit;
mod logger;
mod parent;

#[macro_use]
extern crate log;
extern crate simplelog;

use std::os::fd::AsRawFd;

use anyhow::{anyhow, Result};
use clap::Parser;
use nix::unistd::{fork, pipe, ForkResult};

use crate::{args::Args, child::Child, exit::Exit, logger::Logger, parent::Parent};

fn main() -> Result<()> {
    let args = Args::parse();
    Logger::init(&args)?;

    info!("Started gdb-qemu...");

    info!("Args: {args:#?}");

    Exit::die_on_child_exit()?;

    let (a1, b1) = pipe().map_err(|e| anyhow!("Failed to create pipe #1: {e:}"))?;
    let (a2, b2) = pipe().map_err(|e| anyhow!("Failed to create pipe #2: {e:}"))?;

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: _, .. }) => {
            Parent::new(&args, a1.as_raw_fd(), a2.as_raw_fd()).run()?
        }
        Ok(ForkResult::Child) => Child::new(&args, b1.as_raw_fd(), b2.as_raw_fd()).run()?,
        Err(e) => Err(anyhow!("main: fork failed: {e:}"))?,
    };
    Ok(())
}
