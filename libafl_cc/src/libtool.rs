//! Libtool Wrapper from `LibAFL`
// call make passing LIBTOOL=/path/to/target/release/libafl_libtool

use core::str::FromStr;
use std::{env, path::PathBuf};

use crate::{Error, LIB_EXT, LIB_PREFIX, ToolWrapper};

/// Wrap Clang
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct LibtoolWrapper {
    is_silent: bool,

    name: String,
    linking: bool,
    need_libafl_arg: bool,
    has_libafl_arg: bool,

    output: Option<PathBuf>,
    configurations: Vec<crate::Configuration>,
    parse_args_called: bool,
    base_args: Vec<String>,
}

#[expect(clippy::match_same_arms)] // for the linking = false wip for "shared"
impl ToolWrapper for LibtoolWrapper {
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

        let mut linking = true;
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

        // Libraries needed by libafl on Windows
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
        let configs = self.configurations.clone();
        Ok(configs)
    }

    fn ignore_configurations(&self) -> Result<bool, Error> {
        Ok(false)
    }

    fn command(&mut self) -> Result<Vec<String>, Error> {
        self.command_for_configuration(crate::Configuration::Default)
    }

    fn command_for_configuration(
        &mut self,
        configuration: crate::Configuration,
    ) -> Result<Vec<String>, Error> {
        let mut args = vec![];

        let base_args = self
            .base_args
            .iter()
            .map(|r| {
                let arg_as_path = PathBuf::from(r);
                if r.ends_with('.') {
                    r.to_string()
                } else {
                    if let Some(extension) = arg_as_path.extension() {
                        let extension = extension.to_str().unwrap();
                        let extension_lowercase = extension.to_lowercase();
                        match &extension_lowercase[..] {
                            "lo" | "la" | "so" => configuration.replace_extension(&arg_as_path),
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

        let libtool_path = if let Ok(libtool_dir) = env::var("LIBTOOL_DIR") {
            format!("{libtool_dir}/libtool")
        } else {
            "./libtool".to_string()
        };

        assert!(
            std::path::Path::new(&libtool_path).exists(),
            "Couldn't find libtool. Specify the `LIBTOOL_DIR` environment variable"
        );
        args.push(libtool_path);

        if let Some(output) = self.output.clone() {
            let output = configuration.replace_extension(&output);
            let new_filename = output.into_os_string().into_string().unwrap();
            let dash_c_position = base_args.iter().position(|x| x == "-c");
            if let Some(dash_c_position) = dash_c_position {
                args.extend_from_slice(&base_args[..dash_c_position]);
                args.extend_from_slice(&configuration.to_flags()?);
                args.push("--libafl-ignore-configurations".to_string());
                args.push("-c".to_string());
                args.push("-o".to_string());
                args.push(new_filename);
                args.extend_from_slice(&base_args[(dash_c_position + 1)..]);
            } else {
                args.extend_from_slice(base_args.as_slice());
                args.extend_from_slice(&configuration.to_flags()?);
                args.push("--libafl-ignore-configurations".to_string());
                args.push("-o".to_string());
                args.push(new_filename);
            }
        } else {
            args.extend_from_slice(base_args.as_slice());
            args.extend_from_slice(&configuration.to_flags()?);
        }

        if self.need_libafl_arg && !self.has_libafl_arg {
            return Ok(args);
        }

        Ok(args)
    }

    fn is_linking(&self) -> bool {
        self.linking
    }

    fn filter(&self, _args: &mut Vec<String>) {}

    fn silence(&mut self, value: bool) -> &'_ mut Self {
        self.is_silent = value;
        self
    }

    fn is_silent(&self) -> bool {
        self.is_silent
    }
}

impl Default for LibtoolWrapper {
    /// Create a new Clang Wrapper
    fn default() -> Self {
        Self::new()
    }
}

impl LibtoolWrapper {
    /// Create a new Clang Wrapper
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: String::new(),
            linking: false,
            need_libafl_arg: false,
            has_libafl_arg: false,
            output: None,
            configurations: vec![crate::Configuration::Default],
            parse_args_called: false,
            base_args: vec![],
            is_silent: false,
        }
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
