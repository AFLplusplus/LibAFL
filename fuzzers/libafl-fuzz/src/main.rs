#![deny(clippy::pedantic)]
#![allow(clippy::unsafe_derive_deserialize)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::similar_names)]
use std::{collections::HashMap, path::PathBuf};
mod afl_stats;
mod feedback;
use clap::Parser;
use corpus::{check_autoresume, remove_main_node_file};
mod corpus;
mod executor;
mod fuzzer;
mod hooks;
mod utils;
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
            let res = run_client(state, mgr, &fuzzer_dir, &opt);
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
            run_client(state, mgr, &fuzzer_dir, &opt)
        })
        .cores(&opt.cores)
        .broker_port(opt.broker_port)
        .build()
        .launch()
    {
        Ok(()) => (),
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
    #[arg(value_parser = validate_harness_input_type)]
    harness_input_stdin: Option<String>,

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
    #[arg(env = "AFL_INPUT_LEN_MAX", short = 'G')]
    max_input_len: Option<usize>,
    #[arg(env = "AFL_INPUT_LEN_MIN", short = 'g')]
    min_input_len: Option<usize>,
    // Environment Variables
    #[arg(env = "AFL_BENCH_JUST_ONE")]
    bench_just_one: bool,
    #[arg(env = "AFL_BENCH_UNTIL_CRASH")]
    bench_until_crash: bool,
    #[arg(env = "AFL_HANG_TMOUT", default_value_t = 100)]
    hang_timeout: u64,
    #[arg(env = "AFL_DEBUG_CHILD")]
    debug_child: bool,
    #[arg(env = "AFL_PERSISTENT")]
    is_persistent: bool,
    #[arg(env = "AFL_NO_AUTODICT")]
    no_autodict: bool,
    #[arg(env = "AFL_KILL_SIGNAL", default_value_t = Signal::SIGKILL)]
    kill_signal: Signal,
    #[arg(env = "AFL_MAP_SIZE", default_value_t = 65536,
        value_parser= validate_map_size)]
    map_size: usize,
    #[arg(env = "AFL_IGNORE_TIMEOUTS")]
    ignore_timeouts: bool,
    #[arg(env = "AFL_TMPDIR")]
    cur_input_dir: Option<PathBuf>,
    #[arg(env = "AFL_CRASH_EXITCODE")]
    crash_exitcode: Option<i8>,
    #[arg(env = "AFL_TARGET_ENV", value_parser=parse_target_env)]
    target_env: Option<HashMap<String, String>>,
    #[arg(env = "AFL_CYCLE_SCHEDULES")]
    cycle_schedules: bool,
    #[arg(env = "AFL_CMPLOG_ONLY_NEW")]
    cmplog_only_new: bool,
    #[arg(env = "AFL_PRELOAD")]
    afl_preload: Option<String>,
    #[arg(env = "AFL_AUTORESUME")]
    auto_resume: bool,
    #[arg(env = "AFL_SKIP_BIN_CHECK")]
    skip_bin_check: bool,
    #[arg(env = "AFL_DEFER_FORKSRV")]
    defer_forkserver: bool,
    /// in seconds
    #[arg(env = "AFL_FUZZER_STATS_UPDATE_INTERVAL", default_value = "60")]
    stats_interval: u64,

    // New Environment Variables
    #[arg(env = "AFL_NUM_CORES", value_parser = Cores::from_cmdline)]
    cores: Cores,
    #[arg(env = "AFL_BROKER_PORT", default_value = "1337")]
    broker_port: u16,

    // Seed config
    #[arg(env = "AFL_EXIT_ON_SEED_ISSUES")]
    exit_on_seed_issues: bool,
    // renamed from IGNORE_SEED_PROBLEMS
    #[arg(env = "AFL_IGNORE_SEED_ISSUES")]
    ignore_seed_issues: bool,
    #[arg(env = "AFL_CRASHING_SEED_AS_NEW_CRASH")]
    crash_seed_as_new_crash: bool,

    // TODO:
    #[arg(env = "AFL_FRIDA_PERSISTENT_ADDR")]
    frida_persistent_addr: Option<String>,
    #[arg(env = "AFL_QEMU_CUSTOM_BIN")]
    qemu_custom_bin: bool,
    #[arg(env = "AFL_CS_CUSTOM_BIN")]
    cs_custom_bin: bool,
    use_wine: bool,
    uses_asan: bool,
    frida_mode: bool,
    qemu_mode: bool,
    #[cfg(target_os = "linux")]
    nyx_mode: bool,
    unicorn_mode: bool,
    forkserver_cs: bool,
    no_forkserver: bool,
    crash_mode: bool,
    non_instrumented_mode: bool,
}

const AFL_MAP_SIZE_MIN: usize = usize::pow(2, 3);
const AFL_MAP_SIZE_MAX: usize = usize::pow(2, 30);

const AFL_DEFAULT_INPUT_LEN_MAX: usize = 1_048_576;
const AFL_DEFAULT_INPUT_LEN_MIN: usize = 1;
const OUTPUT_GRACE: u64 = 25;

const PERSIST_SIG: &str = "##SIG_AFL_PERSISTENT##";
const DEFER_SIG: &str = "##SIG_AFL_DEFER_FORKSRV##";
const SHMEM_ENV_VAR: &str = "__AFL_SHM_ID";

fn validate_map_size(s: &str) -> Result<usize, String> {
    let map_size: usize = s
        .parse()
        .map_err(|_| format!("`{s}` isn't a valid unsigned integer"))?;
    if map_size > AFL_MAP_SIZE_MIN && map_size < AFL_MAP_SIZE_MAX {
        Ok(map_size)
    } else {
        Err(format!(
            "AFL_MAP_SIZE not in range {AFL_MAP_SIZE_MIN} (2 ^ 3) - {AFL_MAP_SIZE_MAX} (2 ^ 30)",
        ))
    }
}

fn validate_harness_input_type(s: &str) -> Result<String, String> {
    if s != "@@" {
        return Err("Unknown harness input type. Use \"@@\" for file, omit for stdin ".to_string());
    }
    Ok(s.to_string())
}

/// parse `AFL_TARGET_ENV`; expects: FOO=BAR TEST=ASD
fn parse_target_env(s: &str) -> Result<Option<HashMap<String, String>>, String> {
    let env_regex = regex::Regex::new(r"([^\s=]+)\s*=\s*([^\s]+)").unwrap();
    let mut target_env = HashMap::new();
    for vars in env_regex.captures_iter(s) {
        target_env.insert(
            vars.get(1)
                .ok_or("invalid environment variable format!".to_string())?
                .as_str()
                .to_string(),
            vars.get(2)
                .ok_or("invalid environment variable format!".to_string())?
                .as_str()
                .to_string(),
        );
    }
    Ok(Some(target_env))
}
