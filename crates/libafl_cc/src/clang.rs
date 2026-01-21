//! LLVM compiler Wrapper from `LibAFL`

use core::str::FromStr;
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{CompilerWrapper, Error, LIB_EXT, LIB_PREFIX, ToolWrapper};

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
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LLVMPasses {
    //CmpLogIns,
    /// The `CmpLog` pass
    CmpLogRtn,
    /// The Autotoken pass
    AutoTokens,
    /// The Coverage Accouting (BB metric) pass
    CoverageAccounting,
    /// The dump cfg pass
    DumpCfg,
    #[cfg(unix)]
    /// The `CmpLog` Instruction pass
    CmpLogInstructions,
    /// Instrument caller for sancov coverage
    Ctx,
    /// Function logging
    FunctionLogging,
    /// Git recency mapping for `trace-pc-guard`
    #[cfg(feature = "git-recency")]
    GitRecency,
}

impl LLVMPasses {
    /// Gets the path of the LLVM pass
    #[must_use]
    pub fn path(&self) -> PathBuf {
        match self {
            LLVMPasses::CmpLogRtn => PathBuf::from(env!("OUT_DIR"))
                .join(format!("cmplog-routines-pass.{}", dll_extension())),
            LLVMPasses::AutoTokens => {
                PathBuf::from(env!("OUT_DIR")).join(format!("autotokens-pass.{}", dll_extension()))
            }
            LLVMPasses::CoverageAccounting => PathBuf::from(env!("OUT_DIR"))
                .join(format!("coverage-accounting-pass.{}", dll_extension())),
            LLVMPasses::DumpCfg => {
                PathBuf::from(env!("OUT_DIR")).join(format!("dump-cfg-pass.{}", dll_extension()))
            }
            #[cfg(unix)]
            LLVMPasses::CmpLogInstructions => PathBuf::from(env!("OUT_DIR"))
                .join(format!("cmplog-instructions-pass.{}", dll_extension())),
            LLVMPasses::Ctx => {
                PathBuf::from(env!("OUT_DIR")).join(format!("ctx-pass.{}", dll_extension()))
            }
            LLVMPasses::FunctionLogging => {
                PathBuf::from(env!("OUT_DIR")).join(format!("function-logging.{}", dll_extension()))
            }
            #[cfg(feature = "git-recency")]
            LLVMPasses::GitRecency => {
                PathBuf::from(env!("OUT_DIR")).join(format!("git-recency-pass.{}", dll_extension()))
            }
        }
    }
}

/// Wrap Clang
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct ClangWrapper {
    is_silent: bool,
    optimize: bool,
    wrapped_cc: String,
    wrapped_cxx: String,

    name: String,
    is_cpp: bool,
    is_asm: bool,
    linking: bool,
    shared: bool,
    x_set: bool,
    bit_mode: u32,
    need_libafl_arg: bool,
    has_libafl_arg: bool,

    output: Option<PathBuf>,
    git_recency_mapping_out: Option<PathBuf>,
    configurations: Vec<crate::Configuration>,
    ignoring_configurations: bool,
    parse_args_called: bool,
    base_args: Vec<String>,
    cc_args: Vec<String>,
    link_args: Vec<String>,
    passes: Vec<LLVMPasses>,
    passes_args: Vec<String>,
    passes_linking_args: Vec<String>,
}

#[expect(clippy::match_same_arms)] // for the linking = false wip for "shared"
impl ToolWrapper for ClangWrapper {
    #[expect(clippy::too_many_lines)]
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
                "ToolWrapper::parse_args cannot be called twice on the same instance".to_string(),
            ));
        }
        self.parse_args_called = true;

        if args.len() == 1 {
            return Err(Error::InvalidArguments(
                "LibAFL Tool wrapper - no commands specified. Use me as compiler.".to_string(),
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
            let arg_as_path = Path::new(args[i].as_ref());

            if arg_as_path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("s"))
            {
                self.is_asm = true;
            }

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
                "--libafl-ignore-configurations" | "-print-prog-name=ld" => {
                    self.ignoring_configurations = true;
                    i += 1;
                    continue;
                }
                "--libafl-configurations" => {
                    if i + 1 < args.len() {
                        self.configurations.extend(
                            args[i + 1]
                                .as_ref()
                                .split(',')
                                .map(|x| crate::Configuration::from_str(x).unwrap()),
                        );
                        i += 2;
                        continue;
                    }
                }
                "-o" => {
                    if i + 1 < args.len() {
                        self.output = Some(PathBuf::from(args[i + 1].as_ref()));
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
            }
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
        self.git_recency_mapping_out = None;
        #[cfg(feature = "git-recency")]
        {
            self.git_recency_mapping_out =
                env::var_os(crate::git_recency::GIT_RECENCY_MAPPING_ENV).map(PathBuf::from);
        }

        new_args.push("-g".into());
        if self.optimize {
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
        // `MacOS` has odd linker behavior sometimes
        #[cfg(target_vendor = "apple")]
        if linking || shared {
            new_args.push("-undefined".into());
            new_args.push("dynamic_lookup".into());
        }

        self.base_args.extend(new_args);
        Ok(self)
    }

    fn add_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.base_args.push(arg.as_ref().to_string());
        self
    }

    fn add_configuration(&mut self, configuration: crate::Configuration) -> &'_ mut Self {
        self.configurations.push(configuration);
        self
    }

    fn configurations(&self) -> Result<Vec<crate::Configuration>, Error> {
        let mut configs = self.configurations.clone();
        configs.reverse();
        Ok(configs)
    }

    fn ignore_configurations(&self) -> Result<bool, Error> {
        Ok(self.ignoring_configurations)
    }

    fn command(&mut self) -> Result<Vec<String>, Error> {
        self.command_for_configuration(crate::Configuration::Default)
    }

    #[expect(clippy::too_many_lines)]
    fn command_for_configuration(
        &mut self,
        configuration: crate::Configuration,
    ) -> Result<Vec<String>, Error> {
        let mut args = vec![];
        let mut use_pass = false;
        #[cfg(feature = "git-recency")]
        let mut output_for_sidecar: Option<String> = None;

        if self.is_cpp {
            args.push(self.wrapped_cxx.clone());
        } else {
            args.push(self.wrapped_cc.clone());
        }

        let base_args = self
            .base_args
            .iter()
            .map(|r| {
                let arg_as_path = PathBuf::from(r);
                if r.ends_with('.') {
                    r.clone()
                } else {
                    if let Some(extension) = arg_as_path.extension() {
                        let extension = extension.to_str().unwrap();
                        let extension_lowercase = extension.to_lowercase();
                        match &extension_lowercase[..] {
                            "a" | "la" | "pch" => configuration.replace_extension(&arg_as_path),
                            _ => arg_as_path,
                        }
                    } else {
                        arg_as_path
                    }
                    .into_os_string()
                    .into_string()
                    .unwrap()
                }
            })
            .collect::<Vec<_>>();

        if let crate::Configuration::Default = configuration {
            if let Some(output) = self.output.clone() {
                let output = configuration.replace_extension(&output);
                let new_filename = output.into_os_string().into_string().unwrap();
                args.push("-o".to_string());
                args.push(new_filename.clone());
                #[cfg(feature = "git-recency")]
                {
                    output_for_sidecar = Some(new_filename);
                }
            }
        } else if let Some(output) = self.output.clone() {
            let output = configuration.replace_extension(&output);
            let new_filename = output.into_os_string().into_string().unwrap();
            args.push("-o".to_string());
            args.push(new_filename.clone());
            #[cfg(feature = "git-recency")]
            {
                output_for_sidecar = Some(new_filename);
            }
        } else {
            // No output specified, we need to rewrite the single .c file's name into a -o
            // argument.
            for arg in &base_args {
                let arg_as_path = PathBuf::from(arg);
                if !arg.ends_with('.')
                    && !arg.starts_with('-')
                    && let Some(extension) = arg_as_path.extension()
                {
                    let extension = extension.to_str().unwrap();
                    let extension_lowercase = extension.to_lowercase();
                    match &extension_lowercase[..] {
                        "c" | "cc" | "cxx" | "cpp" => {
                            args.push("-o".to_string());
                            let out_path = if self.linking {
                                configuration
                                    .replace_extension(&PathBuf::from("a.out"))
                                    .into_os_string()
                                    .into_string()
                                    .unwrap()
                            } else {
                                let mut result = configuration.replace_extension(&arg_as_path);
                                result.set_extension("o");
                                result.into_os_string().into_string().unwrap()
                            };
                            args.push(out_path.clone());
                            #[cfg(feature = "git-recency")]
                            {
                                output_for_sidecar = Some(out_path);
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        args.extend_from_slice(base_args.as_slice());

        args.extend_from_slice(&configuration.to_flags()?);

        if self.need_libafl_arg && !self.has_libafl_arg {
            return Ok(args);
        }

        // If we're generating a git-recency mapping, keep `SanitizerCoverage` instrumentation
        // placement stable.
        #[cfg(feature = "git-recency")]
        if self.git_recency_mapping_out.is_some() && !self.linking && !self.is_asm {
            args.push("-mllvm".into());
            args.push("--sanitizer-early-opt-ep".into());
        }

        #[cfg(feature = "git-recency")]
        if self.git_recency_mapping_out.is_some()
            && !self.linking
            && !self.is_asm
            && output_for_sidecar.as_ref().is_some_and(|p| {
                Path::new(p).extension().is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("o") || ext.eq_ignore_ascii_case("obj")
                })
            })
        {
            use_pass = true;

            let pass_path = LLVMPasses::GitRecency
                .path()
                .into_os_string()
                .into_string()
                .unwrap();

            args.push("-Xclang".into());
            args.push("-load".into());
            args.push("-Xclang".into());
            args.push(pass_path.clone());
            args.push("-Xclang".into());
            args.push(format!("-fpass-plugin={pass_path}"));

            let sidecar_path = format!(
                "-libafl-git-recency-sidecar={}.{}",
                output_for_sidecar.as_ref().unwrap(),
                crate::git_recency::SIDECAR_EXT
            );
            args.push("-mllvm".into());
            args.push(sidecar_path);
        }

        for pass in &self.passes {
            use_pass = true;
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
        }
        if !self.is_asm && !self.passes.is_empty() {
            for passes_arg in &self.passes_args {
                args.push("-mllvm".into());
                args.push(passes_arg.into());
            }
        }
        if self.linking {
            if self.x_set {
                args.push("-x".into());
                args.push("none".into());
            }

            args.extend_from_slice(self.link_args.as_slice());

            if use_pass {
                args.extend_from_slice(self.passes_linking_args.as_slice());
            }

            if cfg!(unix) {
                args.push("-pthread".into());
                args.push("-ldl".into());
                args.push("-lm".into());
            }
        } else {
            args.extend_from_slice(self.cc_args.as_slice());
        }

        Ok(args)
    }

    fn is_linking(&self) -> bool {
        self.linking
    }

    fn filter(&self, args: &mut Vec<String>) {
        let blocklist = ["-Werror=unused-command-line-argument", "-Werror"];
        for item in blocklist {
            args.retain(|x| x.clone() != item);
        }
    }

    fn silence(&mut self, value: bool) -> &'_ mut Self {
        self.is_silent = value;
        self
    }

    fn is_silent(&self) -> bool {
        self.is_silent
    }

    fn run(&mut self) -> Result<Option<i32>, Error> {
        let mut last_status = Ok(None);
        let configurations = if self.ignore_configurations()? {
            vec![crate::Configuration::Default]
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

            #[cfg(feature = "git-recency")]
            if status.success()
                && self.linking
                && let Some(mapping_out) = &self.git_recency_mapping_out
            {
                let cwd = env::current_dir().map_err(Error::Io)?;

                let mut link_output: Option<PathBuf> = None;
                let mut i = 1;
                while i + 1 < args.len() {
                    if args[i] == "-o" {
                        link_output = Some(PathBuf::from(&args[i + 1]));
                    }
                    i += 1;
                }
                let Some(link_output) = link_output else {
                    return Err(Error::Unknown(
                        "git recency mapping could not determine link output path".to_string(),
                    ));
                };

                let mut object_files: Vec<PathBuf> = Vec::new();
                for arg in &args[1..] {
                    if arg.starts_with('-') || arg.starts_with('@') {
                        continue;
                    }
                    if Path::new(arg)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("a"))
                    {
                        continue;
                    }
                    if Path::new(arg).extension().is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("o") || ext.eq_ignore_ascii_case("obj")
                    }) {
                        object_files.push(PathBuf::from(arg));
                    }
                }

                crate::git_recency::generate_git_recency_mapping(
                    mapping_out,
                    &link_output,
                    &object_files,
                    &cwd,
                )?;
            }
        }

        last_status
    }
}

impl CompilerWrapper for ClangWrapper {
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
}
impl Default for ClangWrapper {
    /// Create a new Clang Wrapper
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
            name: String::new(),
            is_cpp: false,
            is_asm: false,
            linking: false,
            shared: false,
            x_set: false,
            bit_mode: 0,
            need_libafl_arg: false,
            has_libafl_arg: false,
            output: None,
            git_recency_mapping_out: None,
            configurations: vec![crate::Configuration::Default],
            ignoring_configurations: false,
            parse_args_called: false,
            base_args: vec![],
            cc_args: vec![],
            link_args: vec![],
            passes: vec![],
            passes_args: vec![],
            passes_linking_args: vec![],
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

    /// Disable optimizations, call this before calling `parse_args`
    pub fn dont_optimize(&mut self) -> &'_ mut Self {
        self.optimize = false;
        self
    }

    /// Set cpp mode, call this before calling `parse_args`
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

    /// Add arguments for LLVM passes during linking. For example, ngram needs -lm
    pub fn add_passes_linking_arg<S>(&mut self, arg: S) -> &'_ mut Self
    where
        S: AsRef<str>,
    {
        self.passes_linking_args.push(arg.as_ref().to_string());
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
    use crate::{ClangWrapper, ToolWrapper};

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
