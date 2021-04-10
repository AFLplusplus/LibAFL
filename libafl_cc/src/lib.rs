//! Compiler Wrapper from `LibAFL`

use std::{process::Command, string::String, vec::Vec};

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
    fn from_args(&mut self, args: &[String]) -> Result<&'_ mut Self, Error>;

    /// Add a compiler argument
    fn add_arg(&mut self, arg: String) -> Result<&'_ mut Self, Error>;

    /// Add a compiler argument only when compiling
    fn add_cc_arg(&mut self, arg: String) -> Result<&'_ mut Self, Error>;

    /// Add a compiler argument only when linking
    fn add_link_arg(&mut self, arg: String) -> Result<&'_ mut Self, Error>;

    /// Command to run the compiler
    fn command(&mut self) -> Result<Vec<String>, Error>;

    /// Get if in linking mode
    fn is_linking(&self) -> bool;

    /// Run the compiler
    fn run(&mut self) -> Result<(), Error> {
        let args = self.command()?;
        dbg!(&args);
        if args.is_empty() {
            return Err(Error::InvalidArguments(
                "The number of arguments cannot be 0".into(),
            ));
        }
        let status = match Command::new(&args[0]).args(&args[1..]).status() {
            Ok(s) => s,
            Err(e) => return Err(Error::Io(e)),
        };
        dbg!(status);
        Ok(())
    }
}

/// Wrap Clang
#[allow(clippy::struct_excessive_bools)]
pub struct ClangWrapper {
    optimize: bool,
    wrapped_cc: String,
    wrapped_cxx: String,

    name: String,
    is_cpp: bool,
    linking: bool,
    x_set: bool,
    bit_mode: u32,

    base_args: Vec<String>,
    cc_args: Vec<String>,
    link_args: Vec<String>,
}

#[allow(clippy::match_same_arms)] // for the linking = false wip for "shared"
impl CompilerWrapper for ClangWrapper {
    fn from_args<'a>(&'a mut self, args: &[String]) -> Result<&'a mut Self, Error> {
        let mut new_args = vec![];
        if args.is_empty() {
            return Err(Error::InvalidArguments(
                "The number of arguments cannot be 0".into(),
            ));
        }

        self.name = args[0].clone();
        // Detect C++ compiler looking at the wrapper name
        self.is_cpp = self.is_cpp || self.name.ends_with("++");

        // Sancov flag
        // new_args.push("-fsanitize-coverage=trace-pc-guard".into());

        let mut linking = true;
        // Detect stray -v calls from ./configure scripts.
        if args.len() > 1 && args[1] == "-v" {
            linking = false;
        }

        for arg in &args[1..] {
            match arg.as_str() {
                "-x" => self.x_set = true,
                "-m32" => self.bit_mode = 32,
                "-m64" => self.bit_mode = 64,
                "-c" | "-S" | "-E" => linking = false,
                "-shared" => linking = false, // TODO dynamic list?
                "-Wl,-z,defs" | "-Wl,--no-undefined" => continue,
                _ => (),
            };
            new_args.push(arg.clone());
        }
        self.linking = linking;

        if self.optimize {
            new_args.push("-g".into());
            new_args.push("-O3".into());
            new_args.push("-funroll-loops".into());
        }

        // Fuzzing define common among tools
        new_args.push("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1".into());

        self.base_args = new_args;
        Ok(self)
    }

    fn add_arg(&mut self, arg: String) -> Result<&'_ mut Self, Error> {
        self.base_args.push(arg);
        Ok(self)
    }

    fn add_cc_arg(&mut self, arg: String) -> Result<&'_ mut Self, Error> {
        self.cc_args.push(arg);
        Ok(self)
    }

    fn add_link_arg(&mut self, arg: String) -> Result<&'_ mut Self, Error> {
        self.link_args.push(arg);
        Ok(self)
    }

    fn command(&mut self) -> Result<Vec<String>, Error> {
        let mut args = vec![];
        if self.is_cpp {
            args.push(self.wrapped_cxx.clone());
        } else {
            args.push(self.wrapped_cc.clone());
        }
        args.extend_from_slice(self.base_args.as_slice());
        if self.linking {
            if self.x_set {
                args.push("-x".into());
                args.push("none".into());
            }

            args.extend_from_slice(self.link_args.as_slice());
        } else {
            args.extend_from_slice(self.cc_args.as_slice());
        }

        Ok(args)
    }

    fn is_linking(&self) -> bool {
        self.linking
    }
}

impl ClangWrapper {
    /// Create a new Clang Wrapper
    #[must_use]
    pub fn new(wrapped_cc: &str, wrapped_cxx: &str) -> Self {
        Self {
            optimize: true,
            wrapped_cc: wrapped_cc.into(),
            wrapped_cxx: wrapped_cxx.into(),
            name: "".into(),
            is_cpp: false,
            linking: false,
            x_set: false,
            bit_mode: 0,
            base_args: vec![],
            cc_args: vec![],
            link_args: vec![],
        }
    }

    /// Disable optimizations
    pub fn dont_optimize(&mut self) -> &'_ mut Self {
        self.optimize = false;
        self
    }

    /// set cpp mode
    pub fn is_cpp(&mut self) -> &'_ mut Self {
        self.is_cpp = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClangWrapper, CompilerWrapper};

    #[test]
    fn test_clang_version() {
        ClangWrapper::new("clang", "clang++")
            .from_args(&["my-clang".into(), "-v".into()])
            .unwrap()
            .run()
            .unwrap();
    }
}
