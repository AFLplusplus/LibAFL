use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use crate::options::RawOption::{Directory, Flag};

enum RawOption<'a> {
    Directory(&'a str),
    Flag { name: &'a str, value: i64 },
}

fn parse_option(arg: &str) -> Option<RawOption> {
    if arg.starts_with('-') {
        if let Some((name, value)) = arg.split_at(1).1.split_once('=') {
            if let Ok(value) = value.parse() {
                Some(Flag { name, value })
            } else {
                None
            }
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
pub enum OptionsParseError {
    MultipleModesSelected,
}

impl Display for OptionsParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionsParseError::MultipleModesSelected => {
                f.write_str("multiple modes selected in options")
            }
        }
    }
}

impl Error for OptionsParseError {}

#[derive(Debug)]
pub struct LibfuzzerOptions<'a> {
    mode: LibfuzzerMode,
    dirs: Vec<&'a str>,
    unknown: Vec<&'a str>,
}

impl<'a> LibfuzzerOptions<'a> {
    pub fn new(args: impl Iterator<Item = &'a str>) -> Result<Self, OptionsParseError> {
        let mut builder = LibfuzzerOptionsBuilder::default();
        for arg in args {
            builder.consume(arg)?;
        }
        builder.build()
    }
}

#[derive(Debug, Default)]
struct LibfuzzerOptionsBuilder<'a> {
    mode: Option<LibfuzzerMode>,
    dirs: Vec<&'a str>,
    unknown: Vec<&'a str>,
}

impl<'a> LibfuzzerOptionsBuilder<'a> {
    fn consume(&mut self, arg: &'a str) -> Result<(), OptionsParseError> {
        if let Some(option) = parse_option(arg) {
            match option {
                Directory(dir) => {
                    self.dirs.push(dir);
                }
                Flag { name, value } => match name {
                    "merge" => {
                        if value > 0 {
                            if *self.mode.get_or_insert(LibfuzzerMode::Merge)
                                != LibfuzzerMode::Merge
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                    }
                    "minimize_crash" => {
                        if value > 0 {
                            if *self.mode.get_or_insert(LibfuzzerMode::Cmin) != LibfuzzerMode::Cmin
                            {
                                return Err(OptionsParseError::MultipleModesSelected);
                            }
                        }
                    }
                    _ => self.unknown.push(arg),
                },
            }
        } else {
            self.unknown.push(arg);
        }
        Ok(())
    }

    fn build(self) -> Result<LibfuzzerOptions<'a>, OptionsParseError> {
        Ok(LibfuzzerOptions {
            mode: self.mode.unwrap_or(LibfuzzerMode::Fuzz),
            dirs: self.dirs,
            unknown: self.unknown,
        })
    }
}
