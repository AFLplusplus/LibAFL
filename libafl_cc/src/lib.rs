//! Compiler Wrapper from `LibAFL`

#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
    missing_debug_implementations,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

use core::str;
use std::{path::Path, process::Command};

pub mod ar;
pub use ar::ArWrapper;
pub mod cfg;
pub use cfg::{CfgEdge, ControlFlowGraph, EntryBasicBlockInfo, HasWeight};
pub mod clang;
pub use clang::{ClangWrapper, LLVMPasses};
pub mod libtool;
pub use libtool::LibtoolWrapper;

/// `LibAFL` CC Error Type
#[derive(Debug)]
pub enum Error {
    /// CC Wrapper called with invalid arguments
    InvalidArguments(String),
    /// Io error occurred
    Io(std::io::Error),
    /// Something else happened
    Unknown(String),
}

/// `LibAFL` target configuration
#[derive(Debug, Clone)]
pub enum Configuration {
    /// Default uninstrumented configurations
    Default,
    /// Sanitizing addresses
    AddressSanitizer,
    /// Sanitizing undefined behavior
    UndefinedBehaviorSanitizer,
    /// Generating a coverage map
    GenerateCoverageMap,
    /// Generating coverage profile data for `llvm-cov`
    GenerateCoverageProfile,
    /// Instrumenting for cmplog/redqueen
    CmpLog,
    /// A compound `Configuration`, made up of a list of other `Configuration`s
    Compound(Vec<Self>),
}

impl Configuration {
    /// Get compiler flags for this `Configuration`
    pub fn to_flags(&self) -> Result<Vec<String>, Error> {
        Ok(match self {
            Configuration::Default => vec![],
            // hardware asan is more memory efficient than asan on arm64
            #[cfg(all(
                any(target_os = "linux", target_os = "android"),
                target_arch = "aarch64"
            ))]
            Configuration::AddressSanitizer => vec!["-fsanitize=hwaddress".to_string()],
            #[cfg(not(all(
                any(target_os = "linux", target_os = "android"),
                target_arch = "aarch64"
            )))]
            Configuration::AddressSanitizer => vec!["-fsanitize=address".to_string()],
            Configuration::UndefinedBehaviorSanitizer => vec!["-fsanitize=undefined".to_string()],
            Configuration::GenerateCoverageMap => {
                vec!["-fsanitize-coverage=trace-pc-guard".to_string()]
            }
            Configuration::CmpLog => vec!["-fsanitize-coverage=trace-cmp".to_string()],
            Configuration::GenerateCoverageProfile => {
                vec![
                    "-fprofile-instr-generate".to_string(),
                    "-fcoverage-mapping".to_string(),
                ]
            }
            Configuration::Compound(configurations) => {
                let mut result: Vec<String> = vec![];
                for configuration in configurations {
                    result.extend(configuration.to_flags()?);
                }
                result
            }
        })
    }
    /// Insert a `Configuration` specific 'tag' in the extension of the given file
    #[must_use]
    pub fn replace_extension(&self, path: &Path) -> std::path::PathBuf {
        let mut parent = if let Some(parent) = path.parent() {
            parent.to_path_buf()
        } else {
            std::path::PathBuf::from("")
        };
        let output = path.file_name().unwrap();
        let output = output.to_str().unwrap();

        let new_filename = if let Some((filename, extension)) = output.split_once('.') {
            if let Configuration::Default = self {
                format!("{filename}.{extension}")
            } else {
                format!("{filename}.{self}.{extension}")
            }
        } else if let Configuration::Default = self {
            output.to_string()
        } else {
            format!("{output}.{self}")
        };
        parent.push(new_filename);
        parent
    }
}

impl std::str::FromStr for Configuration {
    type Err = ();
    fn from_str(input: &str) -> Result<Configuration, Self::Err> {
        Ok(match input {
            "asan" => Configuration::AddressSanitizer,
            "ubsan" => Configuration::UndefinedBehaviorSanitizer,
            "coverage" => Configuration::GenerateCoverageMap,
            "llvm-cov" => Configuration::GenerateCoverageProfile,
            "cmplog" => Configuration::CmpLog,
            _ => Configuration::Default,
        })
    }
}

impl std::fmt::Display for Configuration {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Configuration::Default => write!(f, ""),
            Configuration::AddressSanitizer => write!(f, "asan"),
            Configuration::UndefinedBehaviorSanitizer => write!(f, "ubsan"),
            Configuration::GenerateCoverageMap => write!(f, "coverage"),
            Configuration::GenerateCoverageProfile => write!(f, "llvm-cov"),
            Configuration::CmpLog => write!(f, "cmplog"),
            Configuration::Compound(configurations) => {
                let mut result: Vec<String> = vec![];
                for configuration in configurations {
                    result.push(format!("{configuration}"));
                }
                write!(f, "{}", result.join("_"))
            }
        }
    }
}

// TODO macOS
/// extension for static libraries
#[cfg(windows)]
pub const LIB_EXT: &str = "lib";
/// extension for static libraries
#[cfg(not(windows))]
pub const LIB_EXT: &str = "a";

/// prefix for static libraries
#[cfg(windows)]
pub const LIB_PREFIX: &str = "";
/// prefix for static libraries
#[cfg(not(windows))]
pub const LIB_PREFIX: &str = "lib";

/// Wrap a tool hijacking its arguments
pub trait ToolWrapper {
    /// Set the wrapper arguments parsing a command line set of arguments
    fn parse_args<S>(&mut self, args: &[S]) -> Result<&'_ mut Self, Error>
    where
        S: AsRef<str>;

    /// Add an argument
    fn add_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>;

    /// Add arguments
    fn add_args<S>(&mut self, args: &[S]) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        for arg in args {
            self.add_arg(arg);
        }
        self
    }

    /// Add a `Configuration`
    fn add_configuration(&mut self, configuration: Configuration) -> &'_ mut Self;

    /// Command to run the compiler
    fn command(&mut self) -> Result<Vec<String>, Error>;

    /// Command to run the compiler for a given `Configuration`
    #[allow(clippy::too_many_lines)]
    fn command_for_configuration(
        &mut self,
        configuration: Configuration,
    ) -> Result<Vec<String>, Error>;

    /// Get the list of requested `Configuration`s
    fn configurations(&self) -> Result<Vec<Configuration>, Error>;

    /// Whether to ignore the configured `Configurations`. Useful for e.g. nested calls to
    /// `libafl_cc` from `libafl_libtool`.
    fn ignore_configurations(&self) -> Result<bool, Error>;

    /// Get if in linking mode
    fn is_linking(&self) -> bool;

    /// Filter out argumets
    fn filter(&self, _args: &mut Vec<String>) {}

    /// Silences `libafl_cc` output
    fn silence(&mut self, value: bool) -> &'_ mut Self;

    /// Returns `true` if `silence` was called with `true`
    fn is_silent(&self) -> bool;

    /// Run the tool
    fn run(&mut self) -> Result<Option<i32>, Error> {
        let mut last_status = Ok(None);
        let configurations = if self.ignore_configurations()? {
            vec![Configuration::Default]
        } else {
            self.configurations()?
        };
        for configuration in configurations {
            let mut args = self.command_for_configuration(configuration)?;
            self.filter(&mut args);

            if !self.is_silent() {
                dbg!(args.clone());
            }
            if args.is_empty() {
                last_status = Err(Error::InvalidArguments(
                    "The number of arguments cannot be 0".into(),
                ));
                continue;
            }
            let status = match Command::new(&args[0]).args(&args[1..]).status() {
                Ok(s) => s,
                Err(e) => {
                    last_status = Err(Error::Io(e));
                    continue;
                }
            };
            if !self.is_silent() {
                dbg!(status);
            }
            last_status = Ok(status.code());
        }
        last_status
    }
}

/// Wrap a compiler hijacking its arguments
pub trait CompilerWrapper: ToolWrapper {
    /// Add a compiler argument only when compiling
    fn add_cc_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>;

    /// Add a compiler argument only when linking
    fn add_link_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>;

    /// Add compiler arguments only when compiling
    fn add_cc_args<S>(&mut self, args: &[S]) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        for arg in args {
            self.add_cc_arg(arg);
        }
        self
    }

    /// Add compiler arguments only when linking
    fn add_link_args<S>(&mut self, args: &[S]) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        for arg in args {
            self.add_link_arg(arg);
        }
        self
    }

    /// Link static C lib
    fn link_staticlib<S>(&mut self, dir: &Path, name: S) -> &'_ mut Self
    where
        S: AsRef<str>;

    /// Finds the current `python3` version and adds `-lpython3.<version>` as linker argument.
    /// Useful for fuzzers that need libpython, such as `nautilus`-based fuzzers.
    fn link_libpython(&mut self) -> Result<&'_ mut Self, String> {
        Ok(self.add_link_arg(format!("-l{}", find_python3_version()?)))
    }
}

/// Helper function to find the current python3 version, if you need this information at link time.
/// Example output: `python3.11`
/// Example use: `.add_link_arg(format!("-l{}", find_python3_version()?))`
/// Hint: you can use `link_libpython()` directly.
fn find_python3_version() -> Result<String, String> {
    match Command::new("python3").arg("--version").output() {
        Ok(output) => {
            let python_version = str::from_utf8(&output.stdout).unwrap_or_default().trim();
            if python_version.is_empty() {
                return Err("Empty return from python3 --version".to_string());
            }
            let version = python_version.split("Python 3.").nth(1).ok_or_else(|| {
                format!("Could not find Python 3 in version string: {python_version}")
            })?;
            let mut version = version.split('.');
            let version = version.next().ok_or_else(|| {
                format!("Could not split python3 version string {python_version}")
            })?;
            Ok(format!("python3.{version}"))
        }
        Err(err) => Err(format!("Could not execute python3 --version: {err:?}")),
    }
}
