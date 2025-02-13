mod args;

use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
};

use anyhow::{anyhow, Result};
use clap::Parser;

use crate::args::Args;

fn main() -> Result<()> {
    let args = Args::parse();
    for (i, a) in env::args().enumerate() {
        println!("ARG - {i:3}: {a}");
    }
    for (i, (k, v)) in env::vars().enumerate() {
        println!("ENV {i:3}: {k} = {v}");
    }

    let file = File::open(&args.file).map_err(|e| anyhow!("Failed to open maps: {e:}"))?;
    let lines = BufReader::new(file).lines();

    for line in lines {
        println!(
            "{}",
            line.map_err(|e| anyhow!("Failed to read line: {e:}"))?
        );
    }

    Ok(())
}
