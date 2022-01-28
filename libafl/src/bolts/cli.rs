//! A one-size-fits-most approach to defining runtime behavior of `LibAFL` fuzzers
//!
//! The most common pattern of use will be to:
//!
//! - import and call `parse_args`
//! - destructure the subcommands
//! - pull out the options/arguments that are of interest to you/your fuzzer
//! - ignore the rest with `..`
//!
//! There are two provided subcommands: `fuzz` and `replay`. Each one takes a few global options
//! as well as a few that are specific to themselves.
//!
//! # Example (Most Common)
//!
//! The most common usage of the cli parser. Just call `parse_args` and use the results.
//!
//! ```ignore
//! use libafl::bolts::cli::{parse_args, SubCommand};
//! use std::path::{Path, PathBuf};
//!
//! fn fuzz(_: &[PathBuf]) {}
//! fn replay(_: &Path) {}
//!
//! fn main() {
//!     // make sure to add `features = ["cli"]` to the `libafl` crate in `Cargo.toml`
//!     let parsed = parse_args();
//!
//!     match &parsed.command {
//!         // destructure subcommands
//!         SubCommand::Fuzz { tokens, .. } => {
//!             // call appropriate logic, passing in w/e options/args you need
//!             fuzz(tokens)
//!         }
//!         SubCommand::Replay { input_file, .. } => replay(input_file),
//!     }
//!
//!     println!("{:?}", parsed);
//! }
//! ```
//!
//! ## Example (`libafl_qemu`)
//!
//! ```ignore
//! use libafl::bolts::cli::{parse_args, SubCommand};
//! use std::env;
//! use std::path::{Path, PathBuf};
//!
//! // make sure to add `features = ["qemu_cli"]` to the `libafl` crate in `Cargo.toml`
//! use libafl_qemu::Emulator;
//!
//! fn fuzz_with_qemu(_: &[PathBuf], qemu_args: &[String]) {
//!     env::remove_var("LD_LIBRARY_PATH");
//!
//!     let env: Vec<(String, String)> = env::vars().collect();
//!
//!     let emu = Emulator::new(&mut qemu_args.to_vec(), &mut env);
//!     // do other stuff...
//! }
//!
//! fn replay(_: &Path) {}
//!
//! fn main() {
//!     // example command line invocation:
//!     // ./path-to-fuzzer fuzz -x something.dict -- ./path-to-fuzzer -L /path/for/qemu_tack_L ./target --target-opts
//!     let parsed = parse_args();
//!
//!     match &parsed.command {
//!         // destructure subcommands
//!         SubCommand::Fuzz { tokens, .. } => {
//!             // notice that `qemu_args` is available on the FuzzerOptions struct directly, while
//!             // `tokens` needs to be yoinked from the SubCommand::Fuzz variant
//!             fuzz_with_qemu(tokens, &parsed.qemu_args)
//!         }
//!         SubCommand::Replay { input_file, .. } => replay(input_file),
//!     }
//!
//!     println!("{:?}", parsed);
//! }
//!```

use clap::{App, AppSettings, IntoApp, Parser, Subcommand};
#[cfg(feature = "frida_cli")]
use std::error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use super::os::Cores;
use crate::Error;

/// helper function to go from a parsed cli string to a `Duration`
fn parse_timeout(src: &str) -> Result<Duration, Error> {
    Ok(Duration::from_millis(src.parse()?))
}

/// helper function to go from MODULE@0x12345 to (String, usize); aka an instrumentation location
#[cfg(feature = "frida_cli")]
fn parse_instrumentation_location(
    location: &str,
) -> Result<(String, usize), Box<dyn error::Error + Send + Sync + 'static>> {
    let pos = location
        .find('@')
        .ok_or("Expected an '@' in location specifier")?;

    let (module, offset) = location.split_at(pos);

    Ok((
        module.to_string(),
        usize::from_str_radix(
            offset
                .get(1..)
                .ok_or("index out of range")?
                .trim_start_matches("0x"),
            16,
        )?,
    ))
}

/// Top-level container for cli options/arguments/subcommands
#[derive(Parser, Debug)]
#[clap(
    setting(AppSettings::ArgRequiredElseHelp),
    setting(AppSettings::SubcommandPrecedenceOverArg),
    setting(AppSettings::ArgsNegateSubcommands)
)]
#[allow(clippy::struct_excessive_bools)]
pub struct FuzzerOptions {
    /// grouping of subcommands
    #[clap(subcommand)]
    pub command: SubCommand,

    /// timeout for each target execution (milliseconds)
    #[clap(short, long, takes_value = true, default_value = "1000", parse(try_from_str = parse_timeout), global = true)]
    pub timeout: Duration,

    /// whether or not to print debug info
    #[clap(short, long, global = true)]
    pub verbose: bool,

    /// file to which all client output should be written
    #[clap(short, long, global = true)]
    pub stdout: Option<String>,

    /// enable Address Sanitizer (ASAN)
    #[clap(short = 'A', long)]
    pub asan: bool,

    /// enable CmpLog instrumentation
    #[cfg_attr(
        feature = "frida_cli",
        clap(short = 'C', long, global = true, help_heading = "Frida Options")
    )]
    #[cfg_attr(not(feature = "frida_cli"), clap(short = 'C', long))]
    pub cmplog: bool,

    /// enable ASAN leak detection
    #[cfg(feature = "frida_cli")]
    #[clap(short, long, global = true, help_heading = "ASAN Options")]
    pub detect_leaks: bool,

    /// instruct ASAN to continue after a memory error is detected
    #[cfg(feature = "frida_cli")]
    #[clap(long, global = true, help_heading = "ASAN Options")]
    pub continue_on_error: bool,

    /// instruct ASAN to gather (and report) allocation-/free-site backtraces
    #[cfg(feature = "frida_cli")]
    #[clap(long, global = true, help_heading = "ASAN Options")]
    pub allocation_backtraces: bool,

    /// the maximum size that the ASAN allocator should allocate
    #[cfg(feature = "frida_cli")]
    #[clap(
        short,
        long,
        default_value = "1073741824",  // 1_usize << 30
        global = true,
        help_heading = "ASAN Options"
    )]
    pub max_allocation: usize,

    /// the maximum total allocation size that the ASAN allocator should allocate
    #[cfg(feature = "frida_cli")]
    #[clap(
        short = 'M',
        long,
        default_value = "4294967296",  // 1_usize << 32
        global = true,
        help_heading = "ASAN Options"
    )]
    pub max_total_allocation: usize,

    /// instruct ASAN to panic if the max ASAN allocation size is exceeded
    #[cfg(feature = "frida_cli")]
    #[clap(long, global = true, help_heading = "ASAN Options")]
    pub max_allocation_panics: bool,

    /// disable coverage
    #[cfg(feature = "frida_cli")]
    #[clap(long, global = true, help_heading = "Frida Options")]
    pub disable_coverage: bool,

    /// enable DrCov (aarch64 only)
    #[cfg(feature = "frida_cli")]
    #[clap(long, global = true, help_heading = "Frida Options")]
    pub drcov: bool,

    /// locations which will not be instrumented for ASAN or coverage purposes (ex: mod_name@0x12345)
    #[cfg(feature = "frida_cli")]
    #[clap(short = 'D', long, global = true, help_heading = "Frida Options", parse(try_from_str = parse_instrumentation_location), multiple_occurrences = true)]
    pub dont_instrument: Option<Vec<(String, usize)>>,

    /// trailing arguments (after "--") will be passed directly to QEMU
    #[cfg(feature = "qemu_cli")]
    #[clap(last = true, global = true)]
    pub qemu_args: Vec<String>,
}

/// grouping of default subcommands
#[derive(Subcommand, Debug)]
pub enum SubCommand {
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

    /// Replay mode: runs a single input file through the fuzz harness
    #[clap(setting(AppSettings::ArgRequiredElseHelp))]
    Replay {
        /// path to file that should be sent to the harness for crash reproduction
        #[clap(short, long, parse(from_os_str))]
        input_file: PathBuf,

        /// path to harness
        #[clap(short = 'H', long, parse(from_os_str))]
        harness: Option<PathBuf>,

        /// path to harness
        #[clap(short = 'a', long, multiple_occurrences = true)]
        harness_args: Option<Vec<String>>,

        /// Run the same input multiple times
        #[clap(short, long, default_missing_value = "1", min_values = 0)]
        repeat: Option<usize>,
    },
}

impl FuzzerOptions {
    /// given an `App`, add it to `FuzzerOptions` as a subcommand and return the resulting `App`
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use clap::{App, IntoApp, Parser};
    /// use libafl::bolts::cli::FuzzerOptions;
    ///
    /// fn custom_func(_: &str) {}  // not relevant; just for illustrative purposes
    ///
    /// #[derive(Parser, Debug)]
    /// #[clap(name = "custom")]  // the name of the new subcommand
    /// struct CustomFooParser {
    ///     /// a very cromulent option
    ///     #[clap(short, long)]
    ///     bar: String,
    /// }
    ///
    /// fn main() {
    ///     // example command line invocation:
    ///     // ./path-to-bin custom --bar stuff
    ///     
    ///     // clap's builder syntax to define the parser would be fine as well, but here we
    ///     // show the derive option
    ///     let cmd: App = CustomFooParser::into_app();
    ///
    ///     // `with_subcommand` takes an `App`, and returns an `App`
    ///     let parser = FuzzerOptions::with_subcommand(cmd);
    ///
    ///     // use the `App` to parse everything
    ///     let matches = parser.get_matches();
    ///
    ///     // process the results
    ///     if let Some(("custom", sub_matches)) = matches.subcommand() {
    ///         custom_func(sub_matches.value_of("bar").unwrap())
    ///     }
    ///
    ///     println!("{:?}", matches);
    /// }
    /// ```
    #[must_use]
    pub fn with_subcommand(mode: App) -> App {
        let app: App = Self::into_app();
        app.subcommand(mode)
    }
}

/// Parse from `std::env::args_os()`, exit on error
///
/// for more information, see the [cli](super::cli) documentation
#[must_use]
pub fn parse_args() -> FuzzerOptions {
    FuzzerOptions::parse()
}

#[cfg(all(test, feature = "qemu_cli"))]
mod tests {
    use super::*;

    /// pass a standard option and `--` followed by some options that `FuzzerOptions` doesn't know
    /// about; expect the standard option to work normally, and everything after `--` to be
    /// collected into `qemu_args`
    #[test]
    fn standard_option_with_trailing_variable_length_args_collected() {
        let parsed = FuzzerOptions::parse_from([
            "some-command",
            "fuzz",
            "--broker-port",
            "1336",
            "-i",
            "corpus-1",
            "-i",
            "corpus-2",
            "--",
            "-L",
            "qemu-bound",
        ]);
        if let SubCommand::Fuzz { broker_port, .. } = &parsed.command {
            assert_eq!(*broker_port, 1336);
            assert_eq!(parsed.qemu_args, ["-L", "qemu-bound"]);
        }
    }
}
