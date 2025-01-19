use std::path::PathBuf;

use clap::{error::ErrorKind, CommandFactory, Parser};
use libafl_bolts::core_affinity::{CoreId, Cores};

#[readonly::make]
#[derive(Parser, Debug)]
#[clap(author, about, long_about = None)]
#[allow(clippy::module_name_repetitions)]
#[command(
    name = format!("nyx_launcher"),
    about,
    long_about = "Binary fuzzer using NYX"
)]
pub struct FuzzerOptions {
    #[arg(short, long, help = "Input directory")]
    pub input: String,

    #[arg(short, long, help = "Output directory")]
    pub output: String,

    #[arg(short, long, help = "Shared directory")]
    pub share: String,

    #[arg(short, long, help = "Input buffer size")]
    pub buffer_size: usize,

    #[arg(short = 'x', long, help = "Tokens file")]
    pub tokens: Option<String>,

    #[arg(long, help = "Log file")]
    pub log: Option<String>,

    #[arg(long, help = "Timeout in milli-seconds", default_value = "1000")]
    pub timeout: u32,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    pub port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    pub cores: Cores,

    #[arg(long, help = "Cpu cores to use for CmpLog", value_parser = Cores::from_cmdline)]
    pub cmplog_cores: Option<Cores>,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    pub verbose: bool,

    #[clap(long, help = "Enable AFL++ style output", conflicts_with = "verbose")]
    pub tui: bool,

    #[arg(long = "iterations", help = "Maximum numer of iterations")]
    pub iterations: Option<u64>,

    #[arg(
        short = 'r',
        help = "An input to rerun, instead of starting to fuzz. Will ignore all other settings apart from -d."
    )]
    pub rerun_input: Option<PathBuf>,
}

impl FuzzerOptions {
    pub fn input_dir(&self) -> PathBuf {
        PathBuf::from(&self.input)
    }

    pub fn shared_dir(&self) -> PathBuf {
        PathBuf::from(&self.share)
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

    pub fn is_cmplog_core(&self, core_id: CoreId) -> bool {
        self.cmplog_cores
            .as_ref()
            .is_some_and(|c| c.contains(core_id))
    }

    pub fn validate(&self) {
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
