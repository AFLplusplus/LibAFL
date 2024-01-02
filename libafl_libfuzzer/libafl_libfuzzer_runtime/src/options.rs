use core::fmt::{Display, Formatter};
use std::{path::PathBuf, time::Duration};

use libafl::mutators::Tokens;
use serde::{Deserialize, Serialize};

use crate::options::RawOption::{Directory, Flag};

enum RawOption<'a> {
    Directory(&'a str),
    Flag { name: &'a str, value: &'a str },
}

fn parse_option(arg: &str) -> Option<RawOption> {
    if arg.starts_with("--") {
        None
    } else if arg.starts_with('-') {
        if let Some((name, value)) = arg.split_at(1).1.split_once('=') {
            Some(Flag { name, value })
        } else {
            eprintln!("warning: flag {arg} provided without a value; did you mean `{arg}=1'?");
            None
        }
    } else {
        Some(Directory(arg))
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum LibfuzzerMode {
    Fuzz,
    Merge,
    Tmin,
    Report,
}

#[derive(Debug)]
pub enum OptionsParseError<'a> {
    MultipleModesSelected,
    OptionValueParseFailed(&'a str, &'a str),
}

impl<'a> Display for OptionsParseError<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            OptionsParseError::MultipleModesSelected => {
                f.write_str("multiple modes selected in options")
            }
            OptionsParseError::OptionValueParseFailed(name, value) => {
                f.write_fmt(format_args!("couldn't parse value `{value}' for {name}"))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPrefix {
    dir: PathBuf,
    filename_prefix: String,
}

impl ArtifactPrefix {
    fn new(path: &str) -> ArtifactPrefix {
        let mut dir = PathBuf::from(path);
        if path.ends_with(std::path::MAIN_SEPARATOR) {
            Self {
                dir,
                filename_prefix: String::new(),
            }
        } else {
            let filename_prefix = dir.file_name().map_or_else(String::new, |s| {
                s.to_os_string()
                    .into_string()
                    .expect("Provided artifact prefix is not usable")
            });
            dir.pop();
            Self {
                dir,
                filename_prefix,
            }
        }
    }

    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    pub fn filename_prefix(&self) -> &str {
        &self.filename_prefix
    }
}

impl Default for ArtifactPrefix {
    fn default() -> Self {
        Self {
            dir: std::env::current_dir().expect("Must be able to get the current directory!"),
            filename_prefix: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct LibfuzzerOptions {
    fuzzer_name: String,
    mode: LibfuzzerMode,
    artifact_prefix: ArtifactPrefix,
    timeout: Duration,
    grimoire: Option<bool>,
    unicode: bool,
    forks: Option<usize>,
    dict: Option<Tokens>,
    dirs: Vec<PathBuf>,
    ignore_crashes: bool,
    ignore_timeouts: bool,
    ignore_ooms: bool,
    rss_limit: usize,
    malloc_limit: usize,
    dedup: bool,
    shrink: bool,
    skip_tracing: bool,
    tui: bool,
    runs: usize,
    close_fd_mask: u8,
    unknown: Vec<String>,
}

impl LibfuzzerOptions {
    pub fn new<'a>(mut args: impl Iterator<Item = &'a str>) -> Result<Self, OptionsParseError<'a>> {
        let name = args.next().unwrap();
        let name = if let Some(executable) = std::env::current_exe().ok().and_then(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(std::string::ToString::to_string)
        }) {
            executable
        } else {
            name.to_string()
        };
        args.try_fold(LibfuzzerOptionsBuilder::default(), |builder, arg| {
            builder.consume(arg)
        })
        .map(|builder| builder.build(name))
    }

    pub fn fuzzer_name(&self) -> &str {
        &self.fuzzer_name
    }

    pub fn mode(&self) -> &LibfuzzerMode {
        &self.mode
    }

    pub fn artifact_prefix(&self) -> &ArtifactPrefix {
        &self.artifact_prefix
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn grimoire(&self) -> Option<bool> {
        self.grimoire
    }

    pub fn unicode(&self) -> bool {
        self.unicode
    }

    pub fn forks(&self) -> Option<usize> {
        self.forks
    }

    pub fn dict(&self) -> Option<&Tokens> {
        self.dict.as_ref()
    }

    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    pub fn ignore_crashes(&self) -> bool {
        self.ignore_crashes
    }

    pub fn ignore_timeouts(&self) -> bool {
        self.ignore_timeouts
    }

    pub fn ignore_ooms(&self) -> bool {
        self.ignore_ooms
    }

    pub fn rss_limit(&self) -> usize {
        self.rss_limit
    }

    pub fn malloc_limit(&self) -> usize {
        self.malloc_limit
    }

    pub fn dedup(&self) -> bool {
        self.dedup
    }

    pub fn shrink(&self) -> bool {
        self.shrink
    }

    pub fn skip_tracing(&self) -> bool {
        self.skip_tracing
    }

    pub fn tui(&self) -> bool {
        self.tui
    }

    pub fn runs(&self) -> usize {
        self.runs
    }

    pub fn close_fd_mask(&self) -> u8 {
        self.close_fd_mask
    }

    pub fn unknown(&self) -> &[String] {
        &self.unknown
    }
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct LibfuzzerOptionsBuilder<'a> {
    mode: Option<LibfuzzerMode>,
    artifact_prefix: Option<&'a str>,
    timeout: Option<Duration>,
    grimoire: Option<bool>,
    unicode: Option<bool>,
    forks: Option<usize>,
    dict: Option<&'a str>,
    dirs: Vec<&'a str>,
    ignore_crashes: bool,
    ignore_timeouts: bool,
    ignore_ooms: bool,
    rss_limit: Option<usize>,
    malloc_limit: Option<usize>,
    ignore_remaining: bool,
    dedup: bool,
    shrink: bool,
    skip_tracing: bool,
    tui: bool,
    runs: usize,
    close_fd_mask: u8,
    unknown: Vec<&'a str>,
}

macro_rules! parse_or_bail {
    ($name:expr, $parsed:expr, $ty:ty) => {{
        if let Ok(val) = $parsed.parse::<$ty>() {
            val
        } else {
            return Err(OptionsParseError::OptionValueParseFailed($name, $parsed));
        }
    }};
}

impl<'a> LibfuzzerOptionsBuilder<'a> {
    fn consume(mut self, arg: &'a str) -> Result<Self, OptionsParseError<'a>> {
        if !self.ignore_remaining {
            if let Some(option) = parse_option(arg) {
                match option {
                    Directory(dir) => {
                        self.dirs.push(dir);
                    }
                    Flag { name, value } => match name {
                        "merge" => {
                            if parse_or_bail!(name, value, u64) > 0
                                && *self.mode.get_or_insert(LibfuzzerMode::Merge)
                                    != LibfuzzerMode::Merge
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                        "minimize_crash" => {
                            if parse_or_bail!(name, value, u64) > 0
                                && *self.mode.get_or_insert(LibfuzzerMode::Tmin)
                                    != LibfuzzerMode::Tmin
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                        "report" => {
                            if parse_or_bail!(name, value, u64) > 0
                                && *self.mode.get_or_insert(LibfuzzerMode::Report)
                                    != LibfuzzerMode::Report
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                        "grimoire" => self.grimoire = Some(parse_or_bail!(name, value, u64) > 0),
                        "unicode" => self.unicode = Some(parse_or_bail!(name, value, u64) > 0),
                        "artifact_prefix" => {
                            self.artifact_prefix = Some(value);
                        }
                        "timeout" => {
                            self.timeout =
                                Some(value.parse().map(Duration::from_secs_f64).map_err(|_| {
                                    OptionsParseError::OptionValueParseFailed(name, value)
                                })?);
                        }
                        "dict" => self.dict = Some(value),
                        "fork" | "jobs" => {
                            self.forks = Some(parse_or_bail!(name, value, usize));
                        }
                        "ignore_crashes" => {
                            self.ignore_crashes = parse_or_bail!(name, value, u64) > 0;
                        }
                        "ignore_timeouts" => {
                            self.ignore_timeouts = parse_or_bail!(name, value, u64) > 0;
                        }
                        "ignore_ooms" => self.ignore_ooms = parse_or_bail!(name, value, u64) > 0,
                        "rss_limit_mb" => {
                            self.rss_limit = Some(parse_or_bail!(name, value, usize) << 20);
                        }
                        "malloc_limit_mb" => {
                            self.malloc_limit = Some(parse_or_bail!(name, value, usize) << 20);
                        }
                        "ignore_remaining_args" => {
                            self.ignore_remaining = parse_or_bail!(name, value, u64) > 0;
                        }
                        "dedup" => self.dedup = parse_or_bail!(name, value, u64) > 0,
                        "shrink" => self.shrink = parse_or_bail!(name, value, u64) > 0,
                        "skip_tracing" => self.skip_tracing = parse_or_bail!(name, value, u64) > 0,
                        "tui" => self.tui = parse_or_bail!(name, value, u64) > 0,
                        "runs" => self.runs = parse_or_bail!(name, value, usize),
                        "close_fd_mask" => self.close_fd_mask = parse_or_bail!(name, value, u8),
                        _ => {
                            self.unknown.push(arg);
                        }
                    },
                }
            } else {
                self.unknown.push(arg);
            }
        }
        Ok(self)
    }

    fn build(self, fuzzer_name: String) -> LibfuzzerOptions {
        LibfuzzerOptions {
            fuzzer_name,
            mode: self.mode.unwrap_or(LibfuzzerMode::Fuzz),
            artifact_prefix: self
                .artifact_prefix
                .map(ArtifactPrefix::new)
                .unwrap_or_default(),
            timeout: self.timeout.unwrap_or(Duration::from_secs(1200)),
            grimoire: self.grimoire,
            unicode: self.unicode.unwrap_or(true),
            forks: self.forks,
            dict: self.dict.map(|path| {
                Tokens::from_file(path).expect("Couldn't load tokens from specified dictionary")
            }),
            dirs: self.dirs.into_iter().map(PathBuf::from).collect(),
            ignore_crashes: self.ignore_crashes,
            ignore_timeouts: self.ignore_timeouts,
            ignore_ooms: self.ignore_ooms,
            rss_limit: match self.rss_limit.unwrap_or(2 << 30) {
                0 => usize::MAX,
                value => value,
            },
            malloc_limit: match self.malloc_limit.or(self.rss_limit).unwrap_or(2 << 30) {
                0 => usize::MAX,
                value => value,
            },
            dedup: self.dedup,
            shrink: self.shrink,
            skip_tracing: self.skip_tracing,
            tui: self.tui,
            runs: self.runs,
            close_fd_mask: self.close_fd_mask,
            unknown: self
                .unknown
                .into_iter()
                .map(std::string::ToString::to_string)
                .collect(),
        }
    }
}
