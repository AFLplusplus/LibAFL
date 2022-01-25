use fuzzer_options::{parse_args, Commands};
use std::path::PathBuf;

fn fuzz(_: &[PathBuf]) {}
fn replay(_: &PathBuf) {}

fn main() {
    // standard usage
    let parsed = parse_args();

    match &parsed.command {
        // destructure sub-commands
        Commands::Fuzz { token_files, .. } => {
            // call appropriate logic, passing in w/e options/args you need
            fuzz(&token_files)
        }
        Commands::Replay { input_file, .. } => replay(&input_file),
    }
}
