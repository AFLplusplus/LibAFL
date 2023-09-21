use {
    crate::version::Version,
    clap::Parser,
    core::time::Duration,
    libafl::Error,
    libafl_bolts::core_affinity::{CoreId, Cores},
    std::{env, ops::Range, path::PathBuf},
};

#[readonly::make]
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    name = format!("qemu-coverage-{}",env!("CPU_TARGET")),
    version = Version::default(),
    about,
    long_about = "Tool for generating DrCov coverage data using QEMU instrumentation"
)]
pub struct FuzzerOptions {
    #[arg(long, help = "Coverage file")]
    pub coverage: String,

    #[arg(long, help = "Input directory")]
    pub input: String,

    #[arg(long, help = "Output directory")]
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
    pub include: Option<Vec<Range<u64>>>,

    #[arg(long = "exclude", help="Exclude address ranges", value_parser = FuzzerOptions::parse_ranges, conflicts_with="include")]
    pub exclude: Option<Vec<Range<u64>>>,

    #[arg(last = true, help = "Arguments passed to the target")]
    pub args: Vec<String>,
}

impl FuzzerOptions {
    fn parse_timeout(src: &str) -> Result<Duration, Error> {
        Ok(Duration::from_millis(src.parse()?))
    }

    fn parse_ranges(src: &str) -> Result<Vec<Range<u64>>, Error> {
        src.split(',')
            .map(|r| {
                let parts = r.split('-').collect::<Vec<&str>>();
                if parts.len() == 2 {
                    let start = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16)
                        .map_err(|e| {
                            Error::illegal_argument(format!(
                                "Invalid start address: {} ({e:})",
                                parts[0]
                            ))
                        })?;
                    let end = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).map_err(
                        |e| {
                            Error::illegal_argument(format!(
                                "Invalid end address: {} ({e:})",
                                parts[1]
                            ))
                        },
                    )?;
                    Ok(Range { start, end })
                } else {
                    Err(Error::illegal_argument(format!(
                        "Invalid range provided: {r:}"
                    )))
                }
            })
            .collect::<Result<Vec<Range<u64>>, Error>>()
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

    pub fn get_input_dir(&self) -> PathBuf {
        PathBuf::from(&self.input)
    }

    pub fn get_output_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = PathBuf::from(&self.output);
        dir.push(format!("cpu_{:03}", core_id.0));
        dir
    }

    pub fn get_queue_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = self.get_output_dir(core_id).clone();
        dir.push("queue");
        dir
    }

    pub fn get_crashes_dir(&self, core_id: CoreId) -> PathBuf {
        let mut dir = self.get_output_dir(core_id).clone();
        dir.push("crashes");
        dir
    }
}
