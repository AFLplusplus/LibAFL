use fuzzer_options::{parse_args, Commands};
use std::env;
use std::path::{Path, PathBuf};

use libafl_qemu::Emulator;

fn fuzz_with_qemu(_: &[PathBuf], qemu_args: &[String]) {
    env::remove_var("LD_LIBRARY_PATH");

    let env: Vec<(String, String)> = env::vars().collect();

    let _emu = Emulator::new(qemu_args, &env);
    // do other stuff...
}

fn replay(_: &Path) {}

fn main() {
    // example command line invocation:
    // ./path-to-bin fuzz -x something.dict -- -L /path/for/qemu_tack_L
    let parsed = parse_args();

    match &parsed.command {
        // destructure subcommands
        Commands::Fuzz { tokens, .. } => {
            // notice that `qemu_args` is available on the FuzzerOptions struct directly, while
            // `tokens` needs to be yoinked from the Commands::Fuzz variant
            fuzz_with_qemu(tokens, &parsed.qemu_args)
        }
        Commands::Replay { input_file, .. } => replay(input_file),
    }

    println!("{:?}", parsed);
}
