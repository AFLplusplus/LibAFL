use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

use libafl::bolts::os::Cores;

#[cfg(feature = "libafl_qemu")]
use libafl_qemu::filter_qemu_args;

#[cfg(feature = "libafl_qemu")]
mod names {
    pub const CRASHES: &str = "libafl-crashes";
    pub const CORPUS: &str = "libafl-corpus";
    pub const CORES: &str = "libafl-cores";
    pub const TIMEOUT: &str = "libafl-timeout";
    pub const VERBOSE: &str = "libafl-verbose";
    pub const PORT: &str = "libafl-port";
    pub const STDOUT: &str = "libafl-stdout";
    pub const TOKENS: &str = "libafl-tokens";
}

#[cfg(not(feature = "libafl_qemu"))]
mod names {
    pub const CRASHES: &str = "crashes";
    pub const CORPUS: &str = "corpus";
    pub const CORES: &str = "cores";
    pub const TIMEOUT: &str = "timeout";
    pub const VERBOSE: &str = "verbose";
    pub const PORT: &str = "port";
    pub const STDOUT: &str = "stdout";
    pub const TOKENS: &str = "tokens";
}

/// helper function to go from a parsed cli string to a `Duration`
fn parse_timeout(src: &str) -> Duration {
    Duration::from_millis(src.parse::<u64>().unwrap())
}

#[derive(Parser)]
/// Generic options for fuzzer configuration
pub struct FuzzerOptions {
    /// output solutions directory
    #[clap(short = 'o', long = names::CRASHES, default_value = "solutions")]
    pub crashes: PathBuf,

    /// input corpus directories
    #[clap(
        short = 'i',
        long = names::CORPUS,
        default_values = &["corpus"],
        multiple_values = true
    )]
    pub corpora: Vec<PathBuf>,

    /// which cores to bind, i.e. --cores 1,2-4,5
    #[clap(short = 'c', long = names::CORES, default_value = "0", parse(try_from_str = Cores::from_cmdline))]
    pub cores: Cores,

    /// timeout for each target execution (milliseconds)
    #[clap(short = 't', long = names::TIMEOUT, takes_value = true, default_value = "2000", parse(from_str = parse_timeout))]
    pub timeout: Duration,

    /// whether or not to print debug info
    #[clap(short = 'v', long = names::VERBOSE)]
    pub verbose: bool,

    /// port on which the broker should listen
    #[clap(short = 'p', long = names::PORT, default_value = "1337")]
    pub port: u16,

    /// file to which all client output should be written
    #[clap(short = 's', long = names::STDOUT)]
    pub stdout: Option<String>,

    /// paths to fuzzer token files
    #[clap(short = 'x', long = names::TOKENS, multiple_values = true)]
    pub token_files: Vec<PathBuf>,
}

pub fn parse_args() -> FuzzerOptions {
    #[cfg(feature = "libafl_qemu")]
    return FuzzerOptions::parse_from(filter_qemu_args());

    #[cfg(not(feature = "libafl_qemu"))]
    FuzzerOptions::parse()
}
