//! LLVM compiler Wrapper from `LibAFL`

use std::{
    convert::Into,
    env,
    path::{Path, PathBuf},
    string::String,
    vec::Vec,
};

use crate::{CompilerWrapper, Error, LIB_EXT, LIB_PREFIX};

/// The `OUT_DIR` for `LLVM` compiler passes
pub const OUT_DIR: &str = env!("OUT_DIR");

fn dll_extension<'a>() -> &'a str {
    if cfg!(target_os = "windows") {
        "dll"
    } else if cfg!(target_vendor = "apple") {
        "dylib"
    } else {
        "so"
    }
}

include!(concat!(env!("OUT_DIR"), "/clang_constants.rs"));

/// The supported LLVM passes
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LLVMPasses {
    //CmpLogIns,
    /// The CmpLog pass
    CmpLogRtn,
    /// The AFL coverage pass
    AFLCoverage,
    /// The Autotoken pass
    AutoTokens,
    /// The Coverage Accouting (BB metric) pass
    CoverageAccounting,
    /// The dump cfg pass
    DumpCfg,
}

impl LLVMPasses {
    /// Gets the path of the LLVM pass
    #[must_use]
    pub fn path(&self) -> PathBuf {
        match self {
            LLVMPasses::CmpLogRtn => PathBuf::from(env!("OUT_DIR"))
                .join(format!("cmplog-routines-pass.{}", dll_extension())),
            LLVMPasses::AFLCoverage => PathBuf::from(env!("OUT_DIR"))
                .join(format!("afl-coverage-pass.{}", dll_extension())),
            LLVMPasses::AutoTokens => {
                PathBuf::from(env!("OUT_DIR")).join(format!("autotokens-pass.{}", dll_extension()))
            }
            LLVMPasses::CoverageAccounting => PathBuf::from(env!("OUT_DIR"))
                .join(format!("coverage-accounting-pass.{}", dll_extension())),
            LLVMPasses::DumpCfg => {
                PathBuf::from(env!("OUT_DIR")).join(format!("dump-cfg-pass.{}", dll_extension()))
            }
        }
    }
}

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
    shared: bool,
    x_set: bool,
    bit_mode: u32,
    need_libafl_arg: bool,
    has_libafl_arg: bool,
    use_new_pm: bool,

    parse_args_called: bool,
    base_args: Vec<String>,
    cc_args: Vec<String>,
    link_args: Vec<String>,
    passes: Vec<LLVMPasses>,
    passes_args: Vec<String>,
}

#[allow(clippy::match_same_arms)] // for the linking = false wip for "shared"
impl CompilerWrapper for ClangWrapper {
    #[allow(clippy::too_many_lines)]
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
        self.is_cpp = if cfg!(windows) {
            self.is_cpp || self.name.ends_with("++.exe")
        } else {
            self.is_cpp || self.name.ends_with("++")
        };

        // Sancov flag
        // new_args.push("-fsanitize-coverage=trace-pc-guard".into());

        let mut linking = true;
        let mut shared = false;
        // Detect stray -v calls from ./configure scripts.
        if args.len() > 1 && args[1].as_ref() == "-v" {
            if args.len() == 2 {
                self.base_args.push(args[1].as_ref().into());
                return Ok(self);
            }
            linking = false;
        }

        let mut suppress_linking = 0;
        let mut i = 1;
        while i < args.len() {
            match args[i].as_ref() {
                "--libafl-no-link" => {
                    suppress_linking += 1;
                    self.has_libafl_arg = true;
                    i += 1;
                    continue;
                }
                "--libafl" => {
                    suppress_linking += 1337;
                    self.has_libafl_arg = true;
                    i += 1;
                    continue;
                }
                "-fsanitize=fuzzer-no-link" => {
                    suppress_linking += 1;
                    self.has_libafl_arg = true;
                    i += 1;
                    continue;
                }
                "-fsanitize=fuzzer" => {
                    suppress_linking += 1337;
                    self.has_libafl_arg = true;
                    i += 1;
                    continue;
                }
                "-Wl,-z,defs" | "-Wl,--no-undefined" | "--no-undefined" => {
                    i += 1;
                    continue;
                }
                "-z" | "-Wl,-z" => {
                    if i + 1 < args.len()
                        && (args[i + 1].as_ref() == "defs" || args[i + 1].as_ref() == "-Wl,defs")
                    {
                        i += 2;
                        continue;
                    }
                }
                "-x" => self.x_set = true,
                "-m32" => self.bit_mode = 32,
                "-m64" => self.bit_mode = 64,
                "-c" | "-S" | "-E" => linking = false,
                "-shared" => {
                    linking = false;
                    shared = true;
                } // TODO dynamic list?
                _ => (),
            };
            new_args.push(args[i].as_ref().to_string());
            i += 1;
        }
        if linking
            && (suppress_linking > 0 || (self.has_libafl_arg && suppress_linking == 0))
            && suppress_linking < 1337
        {
            linking = false;
            new_args.push(
                PathBuf::from(env!("OUT_DIR"))
                    .join(format!("{LIB_PREFIX}no-link-rt.{LIB_EXT}"))
                    .into_os_string()
                    .into_string()
                    .unwrap(),
            );
        }

        self.linking = linking;
        self.shared = shared;

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
        if linking || shared {
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
        let lib_file = dir
            .join(format!("{LIB_PREFIX}{}.{LIB_EXT}", name.as_ref()))
            .into_os_string()
            .into_string()
            .unwrap();

        if cfg!(unix) {
            if cfg!(target_vendor = "apple") {
                // Same as --whole-archive on linux
                // Without this option, the linker picks the first symbols it finds and does not care if it's a weak or a strong symbol
                // See: <https://stackoverflow.com/questions/13089166/how-to-make-gcc-link-strong-symbol-in-static-library-to-overwrite-weak-symbol>
                self.add_link_arg("-Wl,-force_load").add_link_arg(lib_file)
            } else {
                self.add_link_arg("-Wl,--whole-archive")
                    .add_link_arg(lib_file)
                    .add_link_arg("-Wl,--no-whole-archive")
            }
        } else {
            self.add_link_arg(format!("-Wl,-wholearchive:{lib_file}"))
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
            if self.use_new_pm {
                if let Some(ver) = LIBAFL_CC_LLVM_VERSION {
                    if ver < 16 {
                        args.push("-fexperimental-new-pass-manager".into());
                    }
                }
            } else {
                args.push("-flegacy-pass-manager".into());
            }
        }
        for pass in &self.passes {
            if self.use_new_pm {
                // https://github.com/llvm/llvm-project/issues/56137
                // Need this -Xclang -load -Xclang -<pass>.so thing even with the new PM
                // to pass the arguments to LLVM Passes
                args.push("-Xclang".into());
                args.push("-load".into());
                args.push("-Xclang".into());
                args.push(pass.path().into_os_string().into_string().unwrap());
                args.push("-Xclang".into());
                args.push(format!(
                    "-fpass-plugin={}",
                    pass.path().into_os_string().into_string().unwrap()
                ));
            } else {
                args.push("-Xclang".into());
                args.push("-load".into());
                args.push("-Xclang".into());
                args.push(pass.path().into_os_string().into_string().unwrap());
            }
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
        #[cfg(unix)]
        let use_new_pm = match LIBAFL_CC_LLVM_VERSION {
            Some(ver) => ver >= 14,
            None => false,
        };
        #[cfg(not(unix))]
        let use_new_pm = false;

        Self {
            optimize: true,
            wrapped_cc: CLANG_PATH.into(),
            wrapped_cxx: CLANGXX_PATH.into(),
            name: String::new(),
            is_cpp: false,
            linking: false,
            shared: false,
            x_set: false,
            bit_mode: 0,
            need_libafl_arg: false,
            has_libafl_arg: false,
            use_new_pm,
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

    /// Set if use new llvm pass manager.
    pub fn use_new_pm(&mut self, value: bool) -> &'_ mut Self {
        self.use_new_pm = value;
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{ClangWrapper, CompilerWrapper};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_clang_version() {
        if let Err(res) = ClangWrapper::new()
            .parse_args(&["my-clang", "-v"])
            .unwrap()
            .run()
        {
            println!("Ignored error {res:?} - clang is probably not installed.");
        }
    }
}
