use fuzzer_options::{parse_args, Commands};
use std::path::{Path, PathBuf};

fn fuzz(_: &[PathBuf]) {}
fn replay(_: &Path) {}

fn main() {
    let parsed = parse_args();

    match &parsed.command {
        // destructure subcommands
        Commands::Fuzz { tokens, .. } => {
            // call appropriate logic, passing in w/e options/args you need
            fuzz(tokens)
        }
        Commands::Replay { input_file, .. } => replay(input_file),
    }

    println!("{:?}", parsed);
}
