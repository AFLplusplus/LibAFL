//! Compiler Wrapper from `LibAFL`

use std::{convert::Into, path::Path, process::Command, string::String, vec::Vec};

pub mod clang;
pub use clang::{ClangWrapper, LLVMPasses};

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

/// Wrap a compiler hijacking its arguments
pub trait CompilerWrapper {
    /// Set the wrapper arguments parsing a command line set of arguments
    fn from_args<S>(&mut self, args: &[S]) -> Result<&'_ mut Self, Error>
    where
        S: AsRef<str>;

    /// Add a compiler argument
    fn add_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>;

    /// Add a compiler argument only when compiling
    fn add_cc_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>;

    /// Add a compiler argument only when linking
    fn add_link_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>;

    /// Link static C lib
    fn link_staticlib<S>(&mut self, dir: &Path, name: S) -> &'_ mut Self
    where
        S: AsRef<str>;

    /// Command to run the compiler
    fn command(&mut self) -> Result<Vec<String>, Error>;

    /// Get if in linking mode
    fn is_linking(&self) -> bool;

    /// Silences `libafl_cc` output
    fn silence(&mut self, value: bool) -> &'_ mut Self;

    /// Returns `true` if `silence` was called with `true`
    fn is_silent(&self) -> bool;

    /// Run the compiler
    fn run(&mut self) -> Result<Option<i32>, Error> {
        let args = self.command()?;

        if !self.is_silent() {
            dbg!(&args);
        }
        if args.is_empty() {
            return Err(Error::InvalidArguments(
                "The number of arguments cannot be 0".into(),
            ));
        }
        let status = match Command::new(&args[0]).args(&args[1..]).status() {
            Ok(s) => s,
            Err(e) => return Err(Error::Io(e)),
        };
        if !self.is_silent() {
            dbg!(status);
        }
        Ok(status.code())
    }
}
