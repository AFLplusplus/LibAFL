use core::time::Duration;
use std::{env, ops::Range, path::PathBuf};

use clap::{error::ErrorKind, CommandFactory, Parser};
use libafl::{events::ClientDescription, Error};
use libafl_bolts::core_affinity::{CoreId, Cores};
use libafl_qemu::GuestAddr;

use crate::version::Version;

#[readonly::make]
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = format!("qemu_coverage-{}",env!("CPU_TARGET")),
    version = Version::default(),
    about,
    long_about = "Binary fuzzer using QEMU binary instrumentation"
)]
pub struct FuzzerOptions {
    #[arg(short, long, help = "Input directory")]
    pub input: String,

    #[arg(short, long, help = "Output directory")]
    pub output: String,

    #[arg(short = 'x', long, help = "Tokens file")]
    pub tokens: Option<String>,

    #[cfg(feature = "injections")]
    #[arg(
        short = 'j',
        long,
        help = "Injections TOML or YAML file definition. Filename must end in .toml or .yaml/.yml."
    )]
    pub injections: Option<String>,

    #[arg(long, help = "Log file")]
    pub log: Option<String>,

    #[arg(long, help = "Timeout in milliseconds", default_value = "1000", value_parser = FuzzerOptions::parse_timeout)]
    pub timeout: Duration,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    pub port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    pub cores: Cores,

    #[arg(long, help = "Cpu cores to use for ASan", value_parser = Cores::from_cmdline)]
    pub asan_cores: Option<Cores>,

    #[arg(long, help = "Cpu cores to use for ASan", value_parser = Cores::from_cmdline)]
    pub asan_guest_cores: Option<Cores>,

    #[arg(long, help = "Cpu cores to use for CmpLog", value_parser = Cores::from_cmdline)]
    pub cmplog_cores: Option<Cores>,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    pub verbose: bool,

    #[clap(long, help = "Enable AFL++ style output", conflicts_with = "verbose")]
    pub tui: bool,

    #[clap(long, help = "Enable use of snapshots to restore state")]
    pub snapshots: bool,

    #[arg(long = "iterations", help = "Maximum number of iterations")]
    pub iterations: Option<u64>,

    #[arg(long = "include", help="Include coverage address ranges", value_parser = FuzzerOptions::parse_ranges)]
    pub include: Option<Vec<Range<GuestAddr>>>,

    #[arg(long = "exclude", help="Exclude coverage address ranges", value_parser = FuzzerOptions::parse_ranges, conflicts_with="include")]
    pub exclude: Option<Vec<Range<GuestAddr>>>,

    #[arg(long = "include-asan", help="Include asan address ranges", value_parser = FuzzerOptions::parse_ranges)]
    pub include_asan: Option<Vec<Range<GuestAddr>>>,

    #[arg(long = "exclude-asan", help="Exclude asan address ranges", value_parser = FuzzerOptions::parse_ranges, conflicts_with="include_asan")]
    pub exclude_asan: Option<Vec<Range<GuestAddr>>>,

    #[arg(
        short = 'd',
        help = "Write a DrCov Trace for the current input. Requires -r."
    )]
    pub drcov: Option<PathBuf>,

    #[arg(
        short = 'r',
        help = "An input to rerun, instead of starting to fuzz. Will ignore all other settings apart from -d."
    )]
    pub rerun_input: Option<PathBuf>,

    #[arg(last = true, help = "Arguments passed to the target")]
    pub args: Vec<String>,
}

impl FuzzerOptions {
    fn parse_timeout(src: &str) -> Result<Duration, Error> {
        Ok(Duration::from_millis(src.parse()?))
    }

    fn parse_ranges(src: &str) -> Result<Range<GuestAddr>, Error> {
        let parts = src.split('-').collect::<Vec<&str>>();
        if parts.len() == 2 {
            let start =
                GuestAddr::from_str_radix(parts[0].trim_start_matches("0x"), 16).map_err(|e| {
                    Error::illegal_argument(format!("Invalid start address: {} ({e:})", parts[0]))
                })?;
            let end =
                GuestAddr::from_str_radix(parts[1].trim_start_matches("0x"), 16).map_err(|e| {
                    Error::illegal_argument(format!("Invalid end address: {} ({e:})", parts[1]))
                })?;
            Ok(Range { start, end })
        } else {
            Err(Error::illegal_argument(format!(
                "Invalid range provided: {src:}"
            )))
        }
    }

    pub fn is_asan_core(&self, core_id: CoreId) -> bool {
        self.asan_cores
            .as_ref()
            .is_some_and(|c| c.contains(core_id))
    }

    pub fn is_asan_guest_core(&self, core_id: CoreId) -> bool {
        self.asan_guest_cores
            .as_ref()
            .is_some_and(|c| c.contains(core_id))
    }

    pub fn is_cmplog_core(&self, core_id: CoreId) -> bool {
        self.cmplog_cores
            .as_ref()
            .is_some_and(|c| c.contains(core_id))
    }

    pub fn input_dir(&self) -> PathBuf {
        PathBuf::from(&self.input)
    }

    pub fn output_dir(&self, client_description: ClientDescription) -> PathBuf {
        let mut dir = PathBuf::from(&self.output);
        dir.push(format!("client_{:03}", client_description.id()));
        dir
    }

    pub fn queue_dir(&self, client_description: ClientDescription) -> PathBuf {
        let mut dir = self.output_dir(client_description).clone();
        dir.push("queue");
        dir
    }

    pub fn crashes_dir(&self, client_description: ClientDescription) -> PathBuf {
        let mut dir = self.output_dir(client_description).clone();
        dir.push("crashes");
        dir
    }

    pub fn validate(&self) {
        if let Some(asan_cores) = &self.asan_cores {
            for id in &asan_cores.ids {
                if !self.cores.contains(*id) {
                    let mut cmd = FuzzerOptions::command();
                    cmd.error(
                        ErrorKind::ValueValidation,
                        format!(
                            "Cmplog cores ({}) must be a subset of total cores ({})",
                            asan_cores.cmdline, self.cores.cmdline
                        ),
                    )
                    .exit();
                }
            }
        }

        if let Some(cmplog_cores) = &self.cmplog_cores {
            for id in &cmplog_cores.ids {
                if !self.cores.contains(*id) {
                    let mut cmd = FuzzerOptions::command();
                    cmd.error(
                        ErrorKind::ValueValidation,
                        format!(
                            "Cmplog cores ({}) must be a subset of total cores ({})",
                            cmplog_cores.cmdline, self.cores.cmdline
                        ),
                    )
                    .exit();
                }
            }
        }

        if self.drcov.is_some() && self.rerun_input.is_none() {
            let mut cmd = FuzzerOptions::command();
            cmd.error(
                ErrorKind::ValueValidation,
                "The `drcov` option is only supported with `rerun_input`.".to_string(),
            )
            .exit();
        }
    }
}
