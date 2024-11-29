#![forbid(unexpected_cfgs)]
#![allow(incomplete_features)]
#![warn(clippy::cargo)]
#![allow(ambiguous_glob_reexports)]
#![deny(clippy::cargo_common_metadata)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(
    clippy::unreadable_literal,
    clippy::type_repetition_in_bounds,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::used_underscore_binding,
    clippy::ptr_as_ptr,
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::ptr_cast_constness,
    clippy::unsafe_derive_deserialize,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::into_iter_without_iter, // broken
)]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    //missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        missing_debug_implementations,
        trivial_casts,
        trivial_numeric_casts,
        unused_extern_crates,
        unused_import_braces,
        unused_qualifications,
        unused_must_use,
        //unused_results
    )
)]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

use std::{collections::HashMap, path::PathBuf, time::Duration};
mod env_parser;
mod feedback;
mod scheduler;
mod stages;
use clap::Parser;
use corpus::{check_autoresume, create_dir_if_not_exists};
mod corpus;
mod executor;
mod fuzzer;
mod hooks;
use env_parser::parse_envs;
use fuzzer::run_client;
use libafl::{schedulers::powersched::BaseSchedule, Error};
use libafl_bolts::core_affinity::Cores;
use nix::sys::signal::Signal;
#[cfg(not(feature = "fuzzbench"))]
use {
    corpus::remove_main_node_file,
    libafl::{
        events::{CentralizedLauncher, ClientDescription, EventConfig},
        monitors::MultiMonitor,
    },
    libafl_bolts::shmem::{ShMemProvider, StdShMemProvider},
};
#[cfg(feature = "fuzzbench")]
use {
    libafl::{events::SimpleEventManager, monitors::SimpleMonitor},
    libafl_bolts::core_affinity::CoreId,
};

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
    #[cfg(not(feature = "fuzzbench"))]
    let shmem_provider = StdShMemProvider::new().unwrap();

    // Create our Monitor
    #[cfg(not(feature = "fuzzbench"))]
    let monitor = MultiMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "fuzzbench")]
    let monitor = SimpleMonitor::new(|s| println!("{}", s));

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
    #[cfg(not(feature = "fuzzbench"))]
    let res = CentralizedLauncher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .main_run_client(
            |state: Option<_>, mgr: _, client_description: ClientDescription| {
                println!(
                    "run primary client with id {} on core {}",
                    client_description.id(),
                    client_description.core_id().0
                );
                let fuzzer_dir = opt.output_dir.join("fuzzer_main");
                let _ = check_autoresume(&fuzzer_dir, opt.auto_resume).unwrap();
                let res = run_client(
                    state,
                    mgr,
                    &fuzzer_dir,
                    client_description.core_id(),
                    &opt,
                    true,
                );
                let _ = remove_main_node_file(&fuzzer_dir);
                res
            },
        )
        .secondary_run_client(
            |state: Option<_>, mgr: _, client_description: ClientDescription| {
                println!(
                    "run secondary client with id {} on core {}",
                    client_description.id(),
                    client_description.core_id().0
                );
                let fuzzer_dir = opt
                    .output_dir
                    .join(format!("fuzzer_secondary_{}", client_description.id()));
                let _ = check_autoresume(&fuzzer_dir, opt.auto_resume).unwrap();
                run_client(
                    state,
                    mgr,
                    &fuzzer_dir,
                    client_description.core_id(),
                    &opt,
                    false,
                )
            },
        )
        .cores(&opt.cores.clone().expect("invariant; should never occur"))
        .broker_port(opt.broker_port.unwrap_or(AFL_DEFAULT_BROKER_PORT))
        .build()
        .launch();
    #[cfg(feature = "fuzzbench")]
    let res = {
        let fuzzer_dir = opt.output_dir.join("fuzzer_main");
        let _ = check_autoresume(&fuzzer_dir, opt.auto_resume).unwrap();
        let mgr = SimpleEventManager::new(monitor);
        let res = run_client(None, mgr, &fuzzer_dir, CoreId(0), &opt, true);
        res
    };
    match res {
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
    target_args: Vec<String>,

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
    power_schedule: Option<BaseSchedule>,
    /// enable `CmpLog` by specifying a binary compiled for it.
    #[arg(short = 'c')]
    cmplog: Option<String>,
    /// sync to a foreign fuzzer queue directory (requires -M, can be specified up to 32 times)
    #[arg(short = 'F')]
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
    /// Nyx mode (Note: unlike AFL++, you do not need to specify -Y for parallel nyx fuzzing)
    #[cfg(feature = "nyx")]
    #[arg(short = 'X')]
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

#[allow(dead_code, clippy::struct_excessive_bools)]
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

#[allow(clippy::unnecessary_wraps)] // we need to be compatible with Clap's value_parser
fn parse_cmplog_args(s: &str) -> Result<CmplogOpts, String> {
    Ok(CmplogOpts {
        file_size: s.into(),
        arith_solving: s.contains('A'),
        transform_solving: s.contains('T'),
        exterme_transform_solving: s.contains('X'),
        random_colorization: s.contains('R'),
    })
}
