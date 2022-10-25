//! Uses LLVM compiler Wrapper from `LibAFL`

use libafl_cc::{
    clang::{CLANGXX_PATH, CLANG_PATH, OUT_DIR},
    CompilerWrapper, Error, LLVMPasses, LIB_EXT, LIB_PREFIX,
};

use std::{
    convert::Into,
    env,
    path::{Path, PathBuf},
    string::String,
    vec::Vec,
};

/// Wrap Clang
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct ClangWrapper {
    is_silent: bool,
    optimize: bool,
    wrapped_cc: String,
    wrapped_cxx: String,

    name: String,
    is_cpp: bool,
    linking: bool,
    x_set: bool,
    bit_mode: u32,
    need_libafl_arg: bool,
    has_libafl_arg: bool,

    parse_args_called: bool,
    base_args: Vec<String>,
    cc_args: Vec<String>,
    link_args: Vec<String>,
    passes: Vec<LLVMPasses>,
    passes_args: Vec<String>,
}

#[allow(clippy::match_same_arms)] // for the linking = false wip for "shared"
#[allow(clippy::too_many_lines)]
#[allow(clippy::case_sensitive_file_extension_comparisons)]
impl CompilerWrapper for ClangWrapper {
    fn parse_args<S>(&mut self, args: &[S]) -> Result<&'_ mut Self, Error>
    where
        S: AsRef<str>,
    {
        let mut new_args: Vec<String> = vec![];
        if args.is_empty() {
            return Err(Error::InvalidArguments(
                "The number of arguments cannot be 0".to_string(),
            ));
        }

        if self.parse_args_called {
            return Err(Error::Unknown(
                "CompilerWrapper::parse_args cannot be called twice on the same instance"
                    .to_string(),
            ));
        }
        self.parse_args_called = true;

        if args.len() == 1 {
            return Err(Error::InvalidArguments(
                "LibAFL Compiler wrapper - no commands specified. Use me as compiler.".to_string(),
            ));
        }

        self.name = args[0].as_ref().to_string();
        // Detect C++ compiler looking at the wrapper name
        self.is_cpp = self.is_cpp || self.name.ends_with("++");

        // Sancov flag
        // new_args.push("-fsanitize-coverage=trace-pc-guard".into());

        let mut linking = true;
        // Detect stray -v calls from ./configure scripts.
        if args.len() > 1 && args[1].as_ref() == "-v" {
            linking = false;
        }

        let mut suppress_linking = 0;

        for arg in &args[1..] {
            //TODO: refactor this into a match guard
            if arg.as_ref().starts_with('@')
                && arg.as_ref().ends_with(".rsp")
                && arg.as_ref() != "@./jif.rsp"
            {
                // we are linking!
                suppress_linking += 1;
                self.has_libafl_arg = true;
            }
            match arg.as_ref() {
                //XXX: refactor this
                "-Wl,--no-call-graph-profile-sort" | "-Wl,-u,__sanitizer_options_link_helper" => {
                    continue;
                }
                //"-Wunknown-warning-option" | "-Werror,-Wunknown-warning-option" => {
                "-Werror" => {
                    continue;
                }
                "-Wl,-dead_strip" => {
                    continue;
                }
                "--libafl-no-link" => {
                    suppress_linking += 1;
                    self.has_libafl_arg = true;
                    continue;
                }
                "--libafl" => {
                    suppress_linking += 1337;
                    self.has_libafl_arg = true;
                    continue;
                }
                "-fsanitize=fuzzer-no-link" => {
                    suppress_linking += 1;
                    self.has_libafl_arg = true;
                    continue;
                }
                "-fsanitize=fuzzer" => {
                    suppress_linking += 1337;
                    self.has_libafl_arg = true;
                    continue;
                }
                "-x" => self.x_set = true,
                "-m32" => self.bit_mode = 32,
                "-m64" => self.bit_mode = 64,
                "-c" | "-S" | "-E" => linking = false,
                "-shared" => {
                    linking = false; // TODO dynamic list?
                    new_args.push("-undefined".into());
                    new_args.push("dynamic_lookup".into());
                }
                "-Wl,-z,defs" | "-Wl,--no-undefined" | "--no-undefined" => continue,
                _ => (),
            };

            new_args.push(arg.as_ref().to_string());
        }

        //println!("{:?}", suppress_linking);

        if linking && suppress_linking > 0 && suppress_linking < 1337 {
            linking = false;
            println!("adding no-link-rt");
            new_args.push("-force_load".into());
            new_args.push(
                PathBuf::from(OUT_DIR)
                    .join(format!("{}no-link-rt.{}", LIB_PREFIX, LIB_EXT))
                    .into_os_string()
                    .into_string()
                    .unwrap(),
            );

            new_args.push("-undefined".into());
            new_args.push("dynamic_lookup".into());
        }

        self.linking = linking;

        if self.optimize {
            new_args.push("-g".into());
            new_args.push("-O3".into());
            new_args.push("-funroll-loops".into());
        }

        // Fuzzing define common among tools
        new_args.push("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1".into());

        // Libraries needed by libafl on Windows
        #[cfg(windows)]
        if linking {
            new_args.push("-lws2_32".into());
            new_args.push("-lBcrypt".into());
            new_args.push("-lAdvapi32".into());
        }
        // required by timer API (timer_create, timer_settime)
        #[cfg(target_os = "linux")]
        if linking {
            new_args.push("-lrt".into());
        }
        // MacOS has odd linker behavior sometimes
        #[cfg(target_vendor = "apple")]
        if linking {
            new_args.push("-undefined".into());
            new_args.push("dynamic_lookup".into());
        }

        self.base_args = new_args;
        Ok(self)
    }

    fn add_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.base_args.push(arg.as_ref().to_string());
        self
    }

    fn add_cc_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.cc_args.push(arg.as_ref().to_string());
        self
    }

    fn add_link_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.link_args.push(arg.as_ref().to_string());
        self
    }

    fn link_staticlib<S>(&mut self, dir: &Path, name: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        if cfg!(target_vendor = "apple") {
            //self.add_link_arg("-force_load".into())?;
        } else {
            self.add_link_arg("-Wl,--whole-archive");
        }
        self.add_link_arg(
            dir.join(format!("{}{}.{}", LIB_PREFIX, name.as_ref(), LIB_EXT))
                .into_os_string()
                .into_string()
                .unwrap(),
        );
        if cfg!(target_vendor = "apple") {
            self
        } else {
            self.add_link_arg("-Wl,-no-whole-archive")
        }
    }

    fn command(&mut self) -> Result<Vec<String>, Error> {
        let mut args = vec![];
        if self.is_cpp {
            args.push(self.wrapped_cxx.clone());
        } else {
            args.push(self.wrapped_cc.clone());
        }
        args.extend_from_slice(self.base_args.as_slice());
        if self.need_libafl_arg && !self.has_libafl_arg {
            return Ok(args);
        }

        if !self.passes.is_empty() {
            args.push("-fno-experimental-new-pass-manager".into());
        }
        for pass in &self.passes {
            args.push("-Xclang".into());
            args.push("-load".into());
            args.push("-Xclang".into());
            args.push(pass.path().into_os_string().into_string().unwrap());
        }
        for passes_arg in &self.passes_args {
            args.push("-mllvm".into());
            args.push(passes_arg.into());
        }
        if self.linking {
            if self.x_set {
                args.push("-x".into());
                args.push("none".into());
            }

            args.extend_from_slice(self.link_args.as_slice());

            if cfg!(unix) {
                args.push("-pthread".into());
                args.push("-ldl".into());
            }
        } else {
            args.extend_from_slice(self.cc_args.as_slice());
        }

        Ok(args)
    }

    fn is_linking(&self) -> bool {
        self.linking
    }

    fn silence(&mut self, value: bool) -> &'_ mut Self {
        self.is_silent = value;
        self
    }

    fn is_silent(&self) -> bool {
        self.is_silent
    }
}

impl Default for ClangWrapper {
    /// Create a new Clang Wrapper
    #[must_use]
    fn default() -> Self {
        Self::new()
    }
}

impl ClangWrapper {
    /// Create a new Clang Wrapper
    #[must_use]
    pub fn new() -> Self {
        Self {
            optimize: true,
            wrapped_cc: CLANG_PATH.into(),
            wrapped_cxx: CLANGXX_PATH.into(),
            name: "".into(),
            is_cpp: false,
            linking: false,
            x_set: false,
            bit_mode: 0,
            need_libafl_arg: false,
            has_libafl_arg: false,
            parse_args_called: false,
            base_args: vec![],
            cc_args: vec![],
            link_args: vec![],
            passes: vec![],
            passes_args: vec![],
            is_silent: false,
        }
    }

    /// Sets the wrapped `cc` compiler
    pub fn wrapped_cc(&mut self, cc: String) -> &'_ mut Self {
        self.wrapped_cc = cc;
        self
    }

    /// Sets the wrapped `cxx` compiler
    pub fn wrapped_cxx(&mut self, cxx: String) -> &'_ mut Self {
        self.wrapped_cxx = cxx;
        self
    }

    /// Disable optimizations
    pub fn dont_optimize(&mut self) -> &'_ mut Self {
        self.optimize = false;
        self
    }

    /// Set cpp mode
    pub fn cpp(&mut self, value: bool) -> &'_ mut Self {
        self.is_cpp = value;
        self
    }

    /// Add LLVM pass
    pub fn add_pass(&mut self, pass: LLVMPasses) -> &'_ mut Self {
        self.passes.push(pass);
        self
    }

    /// Add LLVM pass arguments
    pub fn add_passes_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.passes_args.push(arg.as_ref().to_string());
        self
    }

    /// Set if linking
    pub fn linking(&mut self, value: bool) -> &'_ mut Self {
        self.linking = value;
        self
    }

    /// Set if it needs the --libafl arg to add the custom arguments to clang
    pub fn need_libafl_arg(&mut self, value: bool) -> &'_ mut Self {
        self.need_libafl_arg = value;
        self
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_clang_version() {
        if let Err(res) = ClangWrapper::new()
            .parse_args(&["my-clang", "-v"])
            .unwrap()
            .run()
        {
            println!("Ignored error {:?} - clang is probably not installed.", res);
        }
    }
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" | "ng" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ wrapper was called. Expected {:?} to end with c or cxx", dir),
        };

        dir.pop();

        let mut cc = ClangWrapper::new();
        if let Some(code) = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .add_arg("-fsanitize-coverage=trace-pc-guard,trace-cmp")
            // TODO: write the allowlist to a file in /tmp and pass it to the compiler wrapper here
            .add_arg("-fsanitize-coverage-allowlist=/Users/jhertz/jif/chromium/src/headless/jif/allowlist.txt")
            .add_pass(LLVMPasses::CmpLogRtn)
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
