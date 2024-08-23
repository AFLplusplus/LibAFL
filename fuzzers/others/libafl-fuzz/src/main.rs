#![deny(clippy::pedantic)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::{collections::HashMap, path::PathBuf, time::Duration};
mod afl_stats;
mod env_parser;
mod feedback;
mod scheduler;
mod stages;
use clap::Parser;
use corpus::{check_autoresume, create_dir_if_not_exists, remove_main_node_file};
mod corpus;
mod executor;
mod fuzzer;
mod hooks;
use env_parser::parse_envs;
use fuzzer::run_client;
use libafl::{
    events::{CentralizedLauncher, EventConfig},
    monitors::MultiMonitor,
    schedulers::powersched::PowerSchedule,
    Error,
};
use libafl_bolts::{
    core_affinity::{CoreId, Cores},
    shmem::{ShMemProvider, StdShMemProvider},
};
use nix::sys::signal::Signal;

const AFL_DEFAULT_INPUT_LEN_MAX: usize = 1_048_576;
const AFL_DEFAULT_INPUT_LEN_MIN: usize = 1;
const OUTPUT_GRACE: u64 = 25;
pub const AFL_DEFAULT_BROKER_PORT: u16 = 1337;
const PERSIST_SIG: &str = "##SIG_AFL_PERSISTENT##\0";
const DEFER_SIG: &str = "##SIG_AFL_DEFER_FORKSRV##\0";
const SHMEM_ENV_VAR: &str = "__AFL_SHM_ID";
static AFL_HARNESS_FILE_INPUT: &str = "@@";

#[allow(clippy::too_many_lines)]
fn main() {
    env_logger::init();
    let mut opt = Opt::parse();
    parse_envs(&mut opt).expect("invalid configuration");
    executor::check_binary(&mut opt, SHMEM_ENV_VAR).expect("binary to be valid");

    // Create the shared memory map provider for LLMP
    let shmem_provider = StdShMemProvider::new().unwrap();

    // Create our Monitor
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    opt.auto_resume = if opt.auto_resume {
        true
    } else {
        opt.input_dir.as_os_str() == "-"
    };

    create_dir_if_not_exists(&opt.output_dir).expect("could not create output directory");

    // TODO: we need to think about the fuzzer naming scheme since they can be configured in
    // different ways (ASAN/mutators) etc.... and how to autoresume appropriately.
    // Currently we do AFL style resume with hardcoded names.
    // Currently, we will error if we don't find our assigned dir.
    // This will also not work if we use core 1-8 and then later, 16-24
    // since fuzzer names are using core_ids
    match CentralizedLauncher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .main_run_client(|state: Option<_>, mgr: _, core_id: CoreId| {
            println!("run primary client on core {}", core_id.0);
            let fuzzer_dir = opt.output_dir.join("fuzzer_main");
            check_autoresume(&fuzzer_dir, &opt.input_dir, opt.auto_resume).unwrap();
            let res = run_client(state, mgr, &fuzzer_dir, core_id, &opt, true);
            let _ = remove_main_node_file(&fuzzer_dir);
            res
        })
        .secondary_run_client(|state: Option<_>, mgr: _, core_id: CoreId| {
            println!("run secondary client on core {}", core_id.0);
            let fuzzer_dir = opt
                .output_dir
                .join(format!("fuzzer_secondary_{}", core_id.0));
            check_autoresume(&fuzzer_dir, &opt.input_dir, opt.auto_resume).unwrap();
            run_client(state, mgr, &fuzzer_dir, core_id, &opt, false)
        })
        .cores(&opt.cores.clone().expect("invariant; should never occur"))
        .broker_port(opt.broker_port.unwrap_or(AFL_DEFAULT_BROKER_PORT))
        .build()
        .launch()
    {
        Ok(()) => unreachable!(),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    };
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Parser, Clone)]
#[command(
    name = "afl-fuzz",
    about = "afl-fuzz, now with LibAFL!",
    author = "aarnav <aarnavbos@gmail.com>"
)]
/// The Configuration
struct Opt {
    executable: PathBuf,

    // NOTE: afl-fuzz does not accept multiple input directories
    #[arg(short = 'i')]
    input_dir: PathBuf,
    #[arg(short = 'o')]
    output_dir: PathBuf,
    /// file extension for the fuzz test input file (if needed)
    #[arg(short = 'e')]
    input_ext: Option<String>,
    /// use a fixed seed for the RNG
    #[arg(short = 's')]
    rng_seed: Option<u64>,
    /// power schedules compute a seed's performance score: explore(default), fast, exploit, seek, rare, mmopt, coe, lin
    #[arg(short = 'p')]
    power_schedule: Option<PowerSchedule>,
    /// enable `CmpLog` by specifying a binary compiled for it.
    #[arg(short = 'c')]
    cmplog: Option<String>,
    /// sync to a foreign fuzzer queue directory (requires -M, can be specified up to 32 times)
    #[arg(short = 'F', num_args = 32)]
    foreign_sync_dirs: Vec<PathBuf>,
    /// fuzzer dictionary (see README.md)
    #[arg(short = 'x')]
    dicts: Vec<PathBuf>,
    // Environment + CLI variables
    #[arg(short = 'G')]
    max_input_len: Option<usize>,
    #[arg(short = 'g')]
    min_input_len: Option<usize>,
    /// sequential queue selection instead of weighted random
    #[arg(short = 'Z')]
    sequential_queue: bool,
    // TODO: enforce
    #[arg(short = 'm')]
    memory_limit: Option<usize>,
    // TODO: enforce
    #[arg(short = 'V')]
    fuzz_for_seconds: Option<usize>,

    /// timeout for each run
    #[arg(short = 't', default_value_t = 1000)]
    hang_timeout: u64,

    // Environment Variables
    #[clap(skip)]
    bench_just_one: bool,
    #[clap(skip)]
    bench_until_crash: bool,

    #[clap(skip)]
    debug_child: bool,
    #[clap(skip)]
    is_persistent: bool,
    #[clap(skip)]
    no_autodict: bool,
    #[clap(skip)]
    kill_signal: Option<Signal>,
    #[clap(skip)]
    map_size: Option<usize>,
    #[clap(skip)]
    ignore_timeouts: bool,
    #[clap(skip)]
    cur_input_dir: Option<PathBuf>,
    #[clap(skip)]
    crash_exitcode: Option<i8>,
    #[clap(skip)]
    target_env: Option<HashMap<String, String>>,
    #[clap(skip)]
    cycle_schedules: bool,
    #[clap(skip)]
    cmplog_only_new: bool,
    #[clap(skip)]
    afl_preload: Option<String>,
    #[clap(skip)]
    auto_resume: bool,
    #[clap(skip)]
    skip_bin_check: bool,
    #[clap(skip)]
    defer_forkserver: bool,
    /// in seconds
    #[clap(skip)]
    stats_interval: u64,

    // New Environment Variables
    #[clap(skip)]
    cores: Option<Cores>,
    #[clap(skip)]
    broker_port: Option<u16>,

    // Seed config
    #[clap(skip)]
    exit_on_seed_issues: bool,
    // renamed from IGNORE_SEED_PROBLEMS
    #[clap(skip)]
    ignore_seed_issues: bool,
    #[clap(skip)]
    crash_seed_as_new_crash: bool,

    // Cmplog config
    // TODO: actually use this config
    #[arg(short='l', value_parser=parse_cmplog_args)]
    cmplog_opts: Option<CmplogOpts>,

    #[clap(skip)]
    foreign_sync_interval: Duration,
    #[clap(skip)]
    persistent_record: usize,

    // TODO:
    #[clap(skip)]
    frida_persistent_addr: Option<String>,
    #[clap(skip)]
    qemu_custom_bin: bool,
    #[clap(skip)]
    cs_custom_bin: bool,
    /// use qemu-based instrumentation with Wine (Wine mode)
    #[arg(short = 'W')]
    wine_mode: bool,
    #[clap(skip)]
    uses_asan: bool,
    /// use binary-only instrumentation (FRIDA mode)
    #[arg(short = 'O')]
    frida_mode: bool,
    #[clap(skip)]
    frida_asan: bool,
    /// use binary-only instrumentation (QEMU mode)
    #[arg(short = 'Q')]
    qemu_mode: bool,
    #[cfg(target_os = "linux")]
    #[clap(skip)]
    nyx_mode: bool,
    /// use unicorn-based instrumentation (Unicorn mode)
    #[arg(short = 'U')]
    unicorn_mode: bool,
    #[clap(skip)]
    forkserver_cs: bool,
    #[clap(skip)]
    no_forkserver: bool,
    #[clap(skip)]
    crash_mode: bool,
    #[clap(skip)]
    non_instrumented_mode: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CmplogOpts {
    file_size: CmplogFileSize,
    arith_solving: bool,
    transform_solving: bool,
    exterme_transform_solving: bool,
    random_colorization: bool,
}

#[derive(Debug, Clone)]
pub enum CmplogFileSize {
    Small,
    Larger,
    All,
}

impl From<&str> for CmplogFileSize {
    fn from(value: &str) -> Self {
        if value.contains('1') {
            Self::Small
        } else if value.contains('3') {
            Self::All
        } else {
            Self::Larger
        }
    }
}

fn parse_cmplog_args(s: &str) -> Result<CmplogOpts, String> {
    Ok(CmplogOpts {
        file_size: s.into(),
        arith_solving: s.contains('A'),
        transform_solving: s.contains('T'),
        exterme_transform_solving: s.contains('X'),
        random_colorization: s.contains('R'),
    })
}
