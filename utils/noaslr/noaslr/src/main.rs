mod args;

use {
    crate::args::Args,
    anyhow::{anyhow, Result},
    clap::Parser,
    nix::{
        sys::{personality, personality::Persona},
        unistd::execvp,
    },
    std::ffi::CString,
};

fn main() -> Result<()> {
    let args = Args::parse();
    let mut persona = personality::get().map_err(|e| anyhow!("Failed to get personality: {e:}"))?;
    persona |= Persona::ADDR_NO_RANDOMIZE;
    personality::set(persona).map_err(|e| anyhow!("Failed to set personality: {e:}"))?;

    let cargs = args
        .argv()
        .iter()
        .map(|x| CString::new(x.clone()).map_err(|e| anyhow!("Failed to read argument: {e:}")))
        .collect::<Result<Vec<CString>>>()?;

    execvp(&cargs[0], &cargs).map_err(|e| anyhow!("Failed to exceve: {e:}"))?;
    Ok(())
}
