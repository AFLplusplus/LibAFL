//! A one-size-fits-most approach to defining runtime behavior of LibAFL fuzzers
//!
//! The most common pattern of use will be to:
//!
//! - import and call `parse_args`
//! - destructure the sub-commands
//! - pull out the options/arguments that are of interest to you/your fuzzer
//! - ignore the rest with `..`
//!
//! There are two sub-commands: `fuzz` and `replay`. Each one takes a few global options as well
//! as a few that are specific to themselves. An invocation of the standard example (available
//! in the `examples/` directory) is shown below:
//!
//! ```
//! cargo run --example standard fuzz -v -t 5000 -x tokens.dict
//! ```
//!
//! # Examples
//!
//! ```
//! use fuzzer_options::{parse_args, Commands};
//!
//! let parsed = parse_args();
//!
//! match &parsed.command {
//!     // destructure sub-commands
//!     Commands::Fuzz { tokens, .. } => {
//!         // call appropriate logic, passing in w/e options/args you need
//!         fuzz(&tokens)
//!     }
//!     Commands::Replay { input_file, .. } => replay(&input_file),
//! }
//! ```
use clap::{AppSettings, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use libafl::bolts::os::Cores;
use libafl::Error;

/// helper function to go from a parsed cli string to a `Duration`
fn parse_timeout(src: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(src.parse()?))
}

#[derive(Parser, Debug)]
#[clap(
    setting(AppSettings::ArgRequiredElseHelp),
    setting(AppSettings::SubcommandPrecedenceOverArg)
)]
pub struct FuzzerOptions {
    #[clap(subcommand)]
    pub command: Commands,

    /// timeout for each target execution (milliseconds)
    #[clap(short, long, takes_value = true, default_value = "1000", parse(try_from_str = parse_timeout), global = true)]
    pub timeout: Duration,

    /// whether or not to print debug info
    #[clap(short, long, global = true)]
    pub verbose: bool,

    /// file to which all client output should be written
    #[clap(short, long, global = true)]
    pub stdout: Option<String>,

    /// trailing arguments (after "--") will be passed directly to QEMU
    #[cfg(feature = "libafl_qemu")]
    #[clap(last = true, global = true)]
    pub qemu_args: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Fuzz mode: mutates the starting corpus indefinitely, looking for crashes
    Fuzz {
        /// paths to fuzzer token files (aka 'dictionaries')
        #[clap(short = 'x', long, multiple_values = true, parse(from_os_str))]
        tokens: Vec<PathBuf>,

        /// input corpus directories
        #[clap(
            short,
            long,
            default_values = &["corpus/"],
            multiple_values = true,
            parse(from_os_str)
        )]
        input: Vec<PathBuf>,

        /// output solutions directory
        #[clap(short, long, default_value = "solutions/", parse(from_os_str))]
        output: PathBuf,

        /// Spawn a client in each of the provided cores. Use 'all' to select all available
        /// cores. 'none' to run a client without binding to any core.
        /// ex: '1,2-4,6' selects the cores 1, 2, 3, 4, and 6.
        #[clap(short, long, default_value = "0", parse(try_from_str = Cores::from_cmdline))]
        cores: Cores,

        /// port on which the broker should listen
        #[clap(short = 'p', long, default_value = "1337", name = "PORT")]
        broker_port: u16,

        /// ip:port where a remote broker is already listening
        #[clap(short = 'a', long, parse(try_from_str), name = "REMOTE")]
        remote_broker_addr: Option<SocketAddr>,
    },

    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    /// Replay mode: runs a single input file through the fuzz harness
    Replay {
        /// input corpus directories
        #[clap(short, long, parse(from_os_str))]
        input_file: PathBuf,
    },
}

#[must_use]
/// Parse from `std::env::args_os()`, exit on error
pub fn parse_args() -> FuzzerOptions {
    FuzzerOptions::parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "libafl_qemu")]
    /// pass a standard option and `--` followed by some options that FuzzerOptions doesn't know
    /// about; expect the standard option to work normally, and everything after `--` to be
    /// collected into `qemu_args`
    fn standard_option_with_trailing_variable_length_args_collected() {
        let parsed =
            FuzzerOptions::parse_from(["some-command", "--port", "1336", "--", "-L", "qemu-bound"]);
        assert_eq!(parsed.port, 1336);
        assert_eq!(parsed.qemu_args, ["-L", "qemu-bound"])
    }
}
