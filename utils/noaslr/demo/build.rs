use std::error::Error;

use vergen::{Build, Cargo, Emitter, Rustc, Sysinfo};
use vergen_git2::Git2;

fn main() -> Result<(), Box<dyn Error>> {
    let build = Build::all_build();
    let cargo = Cargo::all_cargo();
    let git = Git2::all_git();
    let rustc = Rustc::all_rustc();
    let sysinfo = Sysinfo::all_sysinfo();

    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&git)?
        .add_instructions(&rustc)?
        .add_instructions(&sysinfo)?
        .emit()?;

    Ok(())
}
