use core::time::Duration;
use std::{env, ops::Range, path::PathBuf};

use clap::{error::ErrorKind, CommandFactory, Parser};
use libafl::Error;
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

    #[arg(long, help = "Tokens file")]
    pub tokens: Option<String>,

    #[arg(long, help = "Log file")]
    pub log: Option<String>,

    #[arg(long, help = "Timeout in milli-seconds", default_value = "1000", value_parser = FuzzerOptions::parse_timeout)]
    pub timeout: Duration,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    pub port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    pub cores: Cores,

    #[arg(long, help = "Cpu cores to use to use for ASAN", value_parser = Cores::from_cmdline)]
    pub asan_cores: Option<Cores>,

    #[arg(long, help = "Cpu cores to use to use for CmpLog", value_parser = Cores::from_cmdline)]
    pub cmplog_cores: Option<Cores>,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    pub verbose: bool,

    #[clap(long, help = "Enable AFL++ style output", conflicts_with = "verbose")]
    pub tui: bool,

    #[arg(long = "iterations", help = "Maximum numer of iterations")]
    pub iterations: Option<u64>,

    #[arg(long = "include", help="Include address ranges", value_parser = FuzzerOptions::parse_ranges)]
    pub include: Option<Vec<Range<GuestAddr>>>,

    #[arg(long = "exclude", help="Exclude address ranges", value_parser = FuzzerOptions::parse_ranges, conflicts_with="include")]
    pub exclude: Option<Vec<Range<GuestAddr>>>,

    #[arg(last = true, help = "Arguments passed to the target")]
    pub args: Vec<String>,
}

impl FuzzerOptions {
    fn parse_timeout(src: &str) -> Result<Duration, Error> {
        Ok(Duration::from_millis(src.parse()?))
    }

    fn parse_ranges(src: &str) -> Result<Vec<Range<GuestAddr>>, Error> {
        src.split(',')
            .map(|r| {
                let parts = r.split('-').collect::<Vec<&str>>();
                if parts.len() == 2 {
                    let start = GuestAddr::from_str_radix(parts[0].trim_start_matches("0x"), 16)
                        .map_err(|e| {
                            Error::illegal_argument(format!(
                                "Invalid start address: {} ({e:})",
                                parts[0]
                            ))
                        })?;
                    let end = GuestAddr::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                        .map_err(|e| {
                            Error::illegal_argument(format!(
                                "Invalid end address: {} ({e:})",
                                parts[1]
                            ))
                        })?;
                    Ok(Range { start, end })
                } else {
                    Err(Error::illegal_argument(format!(
                        "Invalid range provided: {r:}"
                    )))
                }
            })
            .collect::<Result<Vec<Range<GuestAddr>>, Error>>()
    }

    pub fn is_asan_core(&self, core_id: CoreId) -> bool {
        self.asan_cores
            .as_ref()
            .map_or(false, |c| c.contains(core_id))
    }

    pub fn is_cmplog_core(&self, core_id: CoreId) -> bool {
        self.cmplog_cores
            .as_ref()
            .map_or(false, |c| c.contains(core_id))
    }

    pub fn input_dir(&self) -> PathBuf {
        PathBuf::from(&self.input)
    }

    pub fn output_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = PathBuf::from(&self.output);
        dir.push(format!("cpu_{:03}", core_id.0));
        dir
    }

    pub fn queue_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = self.output_dir(core_id).clone();
        dir.push("queue");
        dir
    }

    pub fn crashes_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = self.output_dir(core_id).clone();
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
    }
}
