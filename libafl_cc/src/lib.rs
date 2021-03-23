use std::{string::String, vec::Vec};

#[derive(Debug)]
pub enum Error {
    InvalidArguments(String),
    Unknown(String),
}

/// Wrap a compiler hijacking its arguments
pub trait CompilerWrapper {
    /// Set the wrapper arguments parsing a command line set of arguments
    fn from_args<'a>(&'a mut self, args: Vec<String>) -> Result<&'a mut Self, Error>;

    /// Add a compiler argument
    fn add_arg<'a>(&'a mut self, arg: String) -> Result<&'a mut Self, Error>;

    /// Run the compiler
    fn compile(&mut self) -> Result<(), Error>;
}

/// Wrap Clang
pub struct ClangWrapper {
    optimize: bool,
    wrapped_cc: String,
    wrapped_cxx: String,

    name: String,
    is_cpp: bool,
    linking: bool,
    x_set: bool,
    bit_mode: u32,

    args: Vec<String>,
}

impl CompilerWrapper for ClangWrapper {
    fn from_args<'a>(&'a mut self, args: Vec<String>) -> Result<&'a mut Self, Error> {
        let mut new_args = vec![];
        if args.len() < 1 {
            return Err(Error::InvalidArguments(
                "The number of arguments cannot be 0".into(),
            ));
        }

        self.name = args[0].clone();
        // Detect C++ compiler looking at the wrapper name
        self.is_cpp = self.name.ends_with("++");
        if self.is_cpp {
            new_args.push(self.wrapped_cxx.clone());
        } else {
            new_args.push(self.wrapped_cc.clone());
        }

        // Sancov flag
        // new_args.push("-fsanitize-coverage=trace-pc-guard".into());

        let mut linking = true;
        // Detect stray -v calls from ./configure scripts.
        if args.len() == 1 && args[1] == "-v" {
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

        self.args = new_args;
        Ok(self)
    }

    fn add_arg<'a>(&'a mut self, arg: String) -> Result<&'a mut Self, Error> {
        self.args.push(arg);
        Ok(self)
    }

    fn compile(&mut self) -> Result<(), Error> {
        if self.linking {
            if self.x_set {
                self.args.push("-x".into());
                self.args.push("none".into());
            }
        }

        println!("{:?}", self.args);

        Ok(())
    }
}

impl ClangWrapper {
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
            args: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClangWrapper, CompilerWrapper};

    #[test]
    fn test_clang_version() {
        ClangWrapper::new("clang", "clang++")
            .from_args(vec!["my-clang".into(), "-v".into()])
            .unwrap()
            .compile()
            .unwrap();
    }
}
