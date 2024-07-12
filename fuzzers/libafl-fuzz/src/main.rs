#![deny(clippy::pedantic)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

use std::{collections::HashMap, path::PathBuf};
mod afl_stats;
mod env_parser;
mod feedback;
use clap::Parser;
use corpus::{check_autoresume, remove_main_node_file};
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
    /*     let monitor = MultiMonitor::new(|_s| {}); */

    opt.auto_resume = if opt.auto_resume {
        true
    } else {
        opt.input_dir.as_os_str() == "-"
    };

    if !opt.output_dir.exists() {
        std::fs::create_dir(&opt.output_dir).unwrap();
    }

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
            let res = run_client(state, mgr, &fuzzer_dir, &core_id, &opt);
            remove_main_node_file(&fuzzer_dir)
                .expect("error removing main node's is_main_node file");
            res
        })
        .secondary_run_client(|state: Option<_>, mgr: _, core_id: CoreId| {
            println!("run secondary client on core {}", core_id.0);
            let fuzzer_dir = opt
                .output_dir
                .join(format!("fuzzer_secondary_{}", core_id.0));
            check_autoresume(&fuzzer_dir, &opt.input_dir, opt.auto_resume).unwrap();
            run_client(state, mgr, &fuzzer_dir, &core_id, &opt)
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

    #[arg(value_parser = validate_harness_input_stdin)]
    harness_input_type: Option<&'static str>,

    // NOTE: afl-fuzz does not accept multiple input directories
    #[arg(short = 'i')]
    input_dir: PathBuf,
    #[arg(short = 'o')]
    output_dir: PathBuf,
    #[arg(short = 'p')]
    power_schedule: Option<PowerSchedule>,
    #[arg(short = 'c')]
    cmplog_binary: Option<PathBuf>,
    #[arg(short = 'F')]
    foreign_sync_dirs: Vec<PathBuf>,
    // Environment + CLI variables
    #[arg(short = 'G')]
    max_input_len: Option<usize>,
    #[arg(short = 'g')]
    min_input_len: Option<usize>,

    // Environment Variables
    #[clap(skip)]
    bench_just_one: bool,
    #[clap(skip)]
    bench_until_crash: bool,
    #[clap(skip)]
    hang_timeout: u64,
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

    // TODO:
    #[clap(skip)]
    frida_persistent_addr: Option<String>,
    #[clap(skip)]
    qemu_custom_bin: bool,
    #[clap(skip)]
    cs_custom_bin: bool,
    #[clap(skip)]
    use_wine: bool,
    #[clap(skip)]
    uses_asan: bool,
    #[clap(skip)]
    frida_mode: bool,
    #[clap(skip)]
    qemu_mode: bool,
    #[cfg(target_os = "linux")]
    #[clap(skip)]
    nyx_mode: bool,
    #[clap(skip)]
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

const AFL_DEFAULT_INPUT_LEN_MAX: usize = 1_048_576;
const AFL_DEFAULT_INPUT_LEN_MIN: usize = 1;
const OUTPUT_GRACE: u64 = 25;
pub const AFL_DEFAULT_BROKER_PORT: u16 = 1337;
const PERSIST_SIG: &str = "##SIG_AFL_PERSISTENT##";
const DEFER_SIG: &str = "##SIG_AFL_DEFER_FORKSRV##";
const SHMEM_ENV_VAR: &str = "__AFL_SHM_ID";
static AFL_HARNESS_FILE_INPUT: &str = "@@";

fn validate_harness_input_stdin(s: &str) -> Result<&'static str, String> {
    if s != "@@" {
        return Err("Unknown harness input type. Use \"@@\" for file, omit for stdin ".to_string());
    }
    Ok(AFL_HARNESS_FILE_INPUT)
}
