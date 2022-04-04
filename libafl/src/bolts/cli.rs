//! A one-size-fits-most approach to defining runtime behavior of `LibAFL` fuzzers
//!
//! The most common pattern of use will be to import and call `parse_args`.
//!
//! # Example (Most Common)
//!
//! The most common usage of the cli parser. Just call `parse_args` and use the results.
//!
//! ```ignore
//! use libafl::bolts::cli::{parse_args, FuzzerOptions};
//!
//! fn fuzz(options: FuzzerOptions) {}
//! fn replay(options: FuzzerOptions) {}
//!
//! fn main() {
//!     // make sure to add `features = ["cli"]` to the `libafl` crate in `Cargo.toml`
//!     let parsed = parse_args();
//!
//!     // call appropriate logic, passing in parsed options
//!     if parsed.replay.is_some() {
//!         replay(parsed);
//!     } else {
//!         fuzz(parsed);
//!     }
//!
//!     println!("{:?}", parsed);
//! }
//! ```
//!
//! ## Example (`libafl_qemu`)
//!
//! ```ignore
//! use libafl::bolts::cli::{parse_args, FuzzerOptions};
//! use std::env;
//!
//! // make sure to add `features = ["qemu_cli"]` to the `libafl` crate in `Cargo.toml`
//! use libafl_qemu::Emulator;
//!
//! fn fuzz_with_qemu(mut options: FuzzerOptions) {
//!     env::remove_var("LD_LIBRARY_PATH");
//!
//!     let env: Vec<(String, String)> = env::vars().collect();
//!
//!     let emu = Emulator::new(&mut options.qemu_args.to_vec(), &mut env);
//!     // do other stuff...
//! }
//!
//! fn replay(options: FuzzerOptions) {}
//!
//! fn main() {
//!     // example command line invocation:
//!     // ./path-to-fuzzer -x something.dict -- ./path-to-fuzzer -L /path/for/qemu_tack_L ./target --target-opts
//!     let parsed = parse_args();
//!
//!     // call appropriate logic, passing in parsed options
//!     if parsed.replay.is_some() {
//!         replay(parsed);
//!     } else {
//!         fuzz_with_qemu(parsed);
//!     }
//!
//!     println!("{:?}", parsed);
//! }
//!```

use clap::{Command, CommandFactory, Parser};
use serde::{Deserialize, Serialize};
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
#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
#[clap(
    arg_required_else_help(true),
    subcommand_precedence_over_arg(true),
    args_conflicts_with_subcommands(true)
)]
#[allow(clippy::struct_excessive_bools)]
pub struct FuzzerOptions {
    /// timeout for each target execution (milliseconds)
    #[clap(short, long, default_value = "1000", parse(try_from_str = parse_timeout), help_heading = "Fuzz Options")]
    pub timeout: Duration,

    /// whether or not to print debug info
    #[clap(short, long)]
    pub verbose: bool,

    /// file to which all client output should be written
    #[clap(short, long, default_value = "/dev/null")]
    pub stdout: String,

    /// the name of the configuration to use
    #[clap(short, long, default_value = "default configuration")]
    pub configuration: String,

    /// enable Address Sanitizer (ASAN)
    #[clap(short = 'A', long, help_heading = "Fuzz Options")]
    pub asan: bool,

    /// Enable ASAN on each of the provided cores. Use 'all' to select all available
    /// cores. 'none' to run a client without binding to any core.
    /// ex: '1,2-4,6' selects the cores 1, 2, 3, 4, and 6.
    #[cfg(feature = "frida_cli")]
    #[clap(short, long, default_value = "0", parse(try_from_str = Cores::from_cmdline), help_heading = "ASAN Options")]
    pub asan_cores: Cores,

    /// number of fuzz iterations to perform
    #[clap(short = 'I', long, help_heading = "Fuzz Options", default_value = "0")]
    pub iterations: usize,

    /// path to the harness
    #[clap(short = 'H', long, parse(from_os_str), help_heading = "Fuzz Options")]
    pub harness: Option<PathBuf>,

    /// trailing arguments (after "--"); can be passed directly to the harness
    #[cfg(not(feature = "qemu_cli"))]
    #[clap(last = true, name = "HARNESS_ARGS")]
    pub harness_args: Vec<String>,

    /// harness function to call
    #[cfg(feature = "frida_cli")]
    #[clap(
        short = 'F',
        long,
        default_value = "LLVMFuzzerTestOneInput",
        help_heading = "Frida Options"
    )]
    pub harness_function: String,

    /// additional libraries to instrument
    #[cfg(feature = "frida_cli")]
    #[clap(short, long, help_heading = "Frida Options")]
    pub libs_to_instrument: Vec<String>,

    /// enable CmpLog instrumentation
    #[cfg_attr(
        feature = "frida_cli",
        clap(short = 'C', long, help_heading = "Frida Options")
    )]
    #[cfg_attr(
        not(feature = "frida_cli"),
        clap(short = 'C', long, help_heading = "Fuzz Options")
    )]
    pub cmplog: bool,

    /// Enable CmpLog on each of the provided cores. Use 'all' to select all available
    /// cores. 'none' to run a client without binding to any core.
    /// ex: '1,2-4,6' selects the cores 1, 2, 3, 4, and 6.
    #[cfg(feature = "frida_cli")]
    #[clap(short, long, default_value = "0", parse(try_from_str = Cores::from_cmdline), help_heading = "Frida Options")]
    pub cmplog_cores: Cores,

    /// enable ASAN leak detection
    #[cfg(feature = "frida_cli")]
    #[clap(short, long, help_heading = "ASAN Options")]
    pub detect_leaks: bool,

    /// instruct ASAN to continue after a memory error is detected
    #[cfg(feature = "frida_cli")]
    #[clap(long, help_heading = "ASAN Options")]
    pub continue_on_error: bool,

    /// instruct ASAN to gather (and report) allocation-/free-site backtraces
    #[cfg(feature = "frida_cli")]
    #[clap(long, help_heading = "ASAN Options")]
    pub allocation_backtraces: bool,

    /// the maximum size that the ASAN allocator should allocate
    #[cfg(feature = "frida_cli")]
    #[clap(
        short,
        long,
        default_value = "1073741824",  // 1_usize << 30
        help_heading = "ASAN Options"
    )]
    pub max_allocation: usize,

    /// the maximum total allocation size that the ASAN allocator should allocate
    #[cfg(feature = "frida_cli")]
    #[clap(
        short = 'M',
        long,
        default_value = "4294967296",  // 1_usize << 32
        help_heading = "ASAN Options"
    )]
    pub max_total_allocation: usize,

    /// instruct ASAN to panic if the max ASAN allocation size is exceeded
    #[cfg(feature = "frida_cli")]
    #[clap(long, help_heading = "ASAN Options")]
    pub max_allocation_panics: bool,

    /// disable coverage
    #[cfg(feature = "frida_cli")]
    #[clap(long, help_heading = "Frida Options")]
    pub disable_coverage: bool,

    /// enable DrCov (aarch64 only)
    #[cfg(feature = "frida_cli")]
    #[clap(long, help_heading = "Frida Options")]
    pub drcov: bool,

    /// locations which will not be instrumented for ASAN or coverage purposes (ex: mod_name@0x12345)
    #[cfg(feature = "frida_cli")]
    #[clap(short = 'D', long, help_heading = "Frida Options", parse(try_from_str = parse_instrumentation_location), multiple_occurrences = true)]
    pub dont_instrument: Vec<(String, usize)>,

    /// trailing arguments (after "--"); can be passed directly to QEMU
    #[cfg(feature = "qemu_cli")]
    #[clap(last = true)]
    pub qemu_args: Vec<String>,

    /// paths to fuzzer token files (aka 'dictionaries')
    #[clap(
        short = 'x',
        long,
        multiple_values = true,
        parse(from_os_str),
        help_heading = "Fuzz Options"
    )]
    pub tokens: Vec<PathBuf>,

    /// input corpus directories
    #[clap(
        short,
        long,
        default_values = &["corpus/"],
        multiple_values = true,
        parse(from_os_str),
        help_heading = "Corpus Options"
    )]
    pub input: Vec<PathBuf>,

    /// output solutions directory
    #[clap(
        short,
        long,
        default_value = "solutions/",
        parse(from_os_str),
        help_heading = "Corpus Options"
    )]
    pub output: PathBuf,

    /// Spawn a client in each of the provided cores. Use 'all' to select all available
    /// cores. 'none' to run a client without binding to any core.
    /// ex: '1,2-4,6' selects the cores 1, 2, 3, 4, and 6.
    #[clap(short, long, default_value = "0", parse(try_from_str = Cores::from_cmdline))]
    pub cores: Cores,

    /// port on which the broker should listen
    #[clap(short = 'p', long, default_value = "1337", name = "PORT")]
    pub broker_port: u16,

    /// ip:port where a remote broker is already listening
    #[clap(short = 'a', long, parse(try_from_str), name = "REMOTE")]
    pub remote_broker_addr: Option<SocketAddr>,

    /// path to file that should be sent to the harness for crash reproduction
    #[clap(short, long, parse(from_os_str), help_heading = "Replay Options")]
    pub replay: Option<PathBuf>,

    /// Run the same replay input multiple times
    #[clap(
        short = 'R',
        long,
        default_missing_value = "1",
        min_values = 0,
        help_heading = "Replay Options",
        requires = "replay"
    )]
    pub repeat: Option<usize>,
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
    pub fn with_subcommand(mode: Command) -> Command {
        let command: Command = Self::command();
        command.subcommand(mode)
    }
}

/// Parse from `std::env::args_os()`, exit on error
///
/// for more information, see the [cli](super::cli) documentation
#[must_use]
pub fn parse_args() -> FuzzerOptions {
    FuzzerOptions::parse()
}

#[cfg(all(
    test,
    any(feature = "cli", feature = "qemu_cli", feature = "frida_cli")
))]
mod tests {
    use super::*;

    /// pass a standard option and `--` followed by some options that `FuzzerOptions` doesn't know
    /// about; expect the standard option to work normally, and everything after `--` to be
    /// collected into `qemu_args`
    #[test]
    #[cfg(feature = "qemu_cli")]
    fn standard_option_with_trailing_variable_length_args_collected() {
        let parsed = FuzzerOptions::parse_from([
            "some-command",
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
        assert_eq!(parsed.qemu_args, ["-L", "qemu-bound"]);
        assert_eq!(parsed.broker_port, 1336);
    }

    /// pass module without @ to `parse_instrumentation_location`, expect error
    #[test]
    #[cfg(feature = "frida_cli")]
    fn parse_instrumentation_location_fails_without_at_symbol() {
        assert!(parse_instrumentation_location("mod_name0x12345").is_err());
    }

    /// pass module without address to `parse_instrumentation_location`, expect failure
    #[test]
    #[cfg(feature = "frida_cli")]
    fn parse_instrumentation_location_failes_without_address() {
        assert!(parse_instrumentation_location("mod_name@").is_err());
    }

    /// pass location without 0x to `parse_instrumentation_location`, expect value to be parsed
    /// as hex, even without 0x
    #[test]
    #[cfg(feature = "frida_cli")]
    fn parse_instrumentation_location_succeeds_without_0x() {
        assert_eq!(
            parse_instrumentation_location("mod_name@12345").unwrap(),
            (String::from("mod_name"), 74565)
        );
    }

    /// pass location with 0x to `parse_instrumentation_location`, expect value to be parsed as hex
    #[test]
    #[cfg(feature = "frida_cli")]
    fn parse_instrumentation_location_succeeds_with_0x() {
        assert_eq!(
            parse_instrumentation_location("mod_name@0x12345").unwrap(),
            (String::from("mod_name"), 74565)
        );
    }

    /// pass normal value to `parse_timeout` and get back Duration, simple test for happy-path
    #[test]
    #[cfg(feature = "cli")]
    fn parse_timeout_gives_correct_values() {
        assert_eq!(parse_timeout("1525").unwrap(), Duration::from_millis(1525));
    }
}
