use alloc::vec::Vec;
use core::fmt::{Display, Formatter};

use crate::options::RawOption::{Directory, Flag};

enum RawOption<'a> {
    Directory(&'a str),
    Flag { name: &'a str, value: &'a str },
}

fn parse_option(arg: &str) -> Option<RawOption> {
    if arg.starts_with('-') {
        if let Some((name, value)) = arg.split_at(1).1.split_once('=') {
            Some(Flag { name, value })
        } else {
            None
        }
    } else {
        Some(Directory(arg))
    }
}

#[derive(Debug, PartialEq)]
pub enum LibfuzzerMode {
    Fuzz,
    Merge,
    Cmin,
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
            OptionsParseError::OptionValueParseFailed(name, value) => f.write_fmt(format_args!(
                "couldn't parse value `{}' for {}",
                value, name
            )),
        }
    }
}

#[derive(Debug)]
pub struct LibfuzzerOptions<'a> {
    mode: LibfuzzerMode,
    artifact_prefix: Option<&'a str>,
    dirs: Vec<&'a str>,
    unknown: Vec<&'a str>,
}

impl<'a> LibfuzzerOptions<'a> {
    pub fn new(mut args: impl Iterator<Item = &'a str>) -> Result<Self, OptionsParseError<'a>> {
        args.try_fold(LibfuzzerOptionsBuilder::default(), |builder, arg| {
            builder.consume(arg)
        })
        .and_then(|builder| builder.build())
    }

    pub fn mode(&self) -> &LibfuzzerMode {
        &self.mode
    }

    pub fn artifact_prefix(&self) -> Option<&'a str> {
        self.artifact_prefix.clone()
    }

    pub fn dirs(&self) -> &[&'a str] {
        &self.dirs
    }

    pub fn unknown(&self) -> &[&'a str] {
        &self.unknown
    }
}

#[derive(Debug, Default)]
struct LibfuzzerOptionsBuilder<'a> {
    mode: Option<LibfuzzerMode>,
    artifact_prefix: Option<&'a str>,
    dirs: Vec<&'a str>,
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
    fn consume(mut self, arg: &'a str) -> Result<Self, OptionsParseError> {
        if let Some(option) = parse_option(arg) {
            match option {
                Directory(dir) => {
                    self.dirs.push(dir);
                }
                Flag { name, value } => match name {
                    "merge" => {
                        if parse_or_bail!(name, value, u64) > 0 {
                            if *self.mode.get_or_insert(LibfuzzerMode::Merge)
                                != LibfuzzerMode::Merge
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                    }
                    "minimize_crash" => {
                        if parse_or_bail!(name, value, u64) > 0 {
                            if *self.mode.get_or_insert(LibfuzzerMode::Cmin) != LibfuzzerMode::Cmin
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                    }
                    "artifact_prefix" => {}
                    _ => self.unknown.push(arg),
                },
            }
        } else {
            self.unknown.push(arg);
        }
        Ok(self)
    }

    fn build(self) -> Result<LibfuzzerOptions<'a>, OptionsParseError<'a>> {
        Ok(LibfuzzerOptions {
            mode: self.mode.unwrap_or(LibfuzzerMode::Fuzz),
            artifact_prefix: self.artifact_prefix,
            dirs: self.dirs,
            unknown: self.unknown,
        })
    }
}
