//! A singlethreaded QEMU fuzzer that can auto-restart.

use clap::{App, Arg};
use core::{cell::RefCell, time::Duration};
#[cfg(unix)]
use nix::{self, unistd::dup};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    process,
};

use libafl::{
    bolts::{
        current_nanos, current_time,
        os::dup2,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
    },
    corpus::{Corpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleRestartingEventManager,
    executors::{ExitKind, ShadowExecutor, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        scheduled::{havoc_mutations, StdScheduledMutator},
        tokens_mutations, I2SRandReplace, Tokens,
    },
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    stages::{ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, HasMetadata, StdState},
    Error,
};
use libafl_qemu::{
    amd64::Amd64Regs,
    asan::QemuAsanHelper,
    cmplog,
    cmplog::{CmpLogObserver, QemuCmpLogHelper},
    edges,
    edges::QemuEdgeCoverageHelper,
    elf::EasyElf,
    emu, filter_qemu_args, init_with_asan,
    snapshot::QemuSnapshotHelper,
    MmapPerms, QemuExecutor,
};

/// The fuzzer main
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    let mut args: Vec<String> = env::args().collect();
    let mut env: Vec<(String, String)> = env::vars().collect();
    init_with_asan(&mut args, &mut env);

    let res = match App::new("libafl_qemu_fuzzbench")
        .version("0.4.0")
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer with QEMU for Fuzzbench")
        .arg(
            Arg::new("out")
                .about("The directory to place finds in ('corpus')")
                .long("libafl-out")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("in")
                .about("The directory to read initial inputs from ('seeds')")
                .long("libafl-in")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("tokens")
                .long("libafl-tokens")
                .about("A file to read tokens from, to be used during fuzzing")
                .takes_value(true),
        )
        .arg(
            Arg::new("logfile")
                .long("libafl-logfile")
                .about("Duplicates all output to this file")
                .default_value("libafl.log"),
        )
        .arg(
            Arg::new("timeout")
                .long("libafl-timeout")
                .about("Timeout for each individual execution, in milliseconds")
                .default_value("1000"),
        )
        .try_get_matches_from(filter_qemu_args())
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, --libafl-in <input> --libafl-out <output>\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err.info,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(res.value_of("out").unwrap().to_string());
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(res.value_of("in").unwrap().to_string());
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let tokens = res.value_of("tokens").map(PathBuf::from);

    let logfile = PathBuf::from(res.value_of("logfile").unwrap().to_string());

    let timeout = Duration::from_millis(
        res.value_of("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    fuzz(out_dir, crashes, in_dir, tokens, logfile, timeout)
        .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: PathBuf,
    tokenfile: Option<PathBuf>,
    logfile: PathBuf,
    timeout: Duration,
) -> Result<(), Error> {
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu::binary_path(), &mut elf_buffer)?;

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu::load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    println!("LLVMFuzzerTestOneInput @ {:#x}", test_one_input_ptr);

    emu::set_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    emu::run();

    println!(
        "Break at {:#x}",
        emu::read_reg::<_, u64>(Amd64Regs::Rip).unwrap()
    );

    let stack_ptr: u64 = emu::read_reg(Amd64Regs::Rsp).unwrap();
    let mut ret_addr = [0u64];
    emu::read_mem(stack_ptr, &mut ret_addr);
    let ret_addr = ret_addr[0];

    println!("Stack pointer = {:#x}", stack_ptr);
    println!("Return address = {:#x}", ret_addr);

    emu::remove_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    emu::set_breakpoint(ret_addr); // LLVMFuzzerTestOneInput ret addr

    let input_addr = emu::map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
    println!("Placing input at {:#x}", input_addr);

    let log = RefCell::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&logfile)?,
    );

    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{}", s).unwrap();
        #[cfg(windows)]
        println!("{}", s);
        writeln!(log.borrow_mut(), "{:?} {}", current_time(), s).unwrap();
    });

    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    // Create an observation channel using the coverage map
    let edges = unsafe { &mut edges::EDGES_MAP };
    let edges_counter = unsafe { &mut edges::MAX_EDGES_NUM };
    let edges_observer =
        HitcountsMapObserver::new(VariableMapObserver::new("edges", edges, edges_counter));

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Create an observation channel using cmplog map
    let cmplog_observer = CmpLogObserver::new("cmplog", unsafe { &mut cmplog::CMPLOG_MAP }, true);

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            OnDiskCorpus::new(corpus_dir).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // They are the data related to the feedbacks that you want to persist in the State.
            tuple_list!(feedback_state),
        )
    });

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > 4096 {
            buf = &buf[0..4096];
            len = 4096;
        }

        emu::write_mem(input_addr, buf);

        emu::write_reg(Amd64Regs::Rdi, input_addr).unwrap();
        emu::write_reg(Amd64Regs::Rsi, len).unwrap();
        emu::write_reg(Amd64Regs::Rip, test_one_input_ptr).unwrap();
        emu::write_reg(Amd64Regs::Rsp, stack_ptr).unwrap();

        emu::run();

        ExitKind::Ok
    };

    let executor = QemuExecutor::new(
        &mut harness,
        tuple_list!(
            QemuEdgeCoverageHelper::new(),
            QemuCmpLogHelper::new(),
            QemuAsanHelper::new(),
            //QemuSnapshotHelper::new()
        ),
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )?;

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let executor = TimeoutExecutor::new(executor, timeout);
    // Show the cmplog observer
    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    // Read tokens
    if let Some(tokenfile) = tokenfile {
        if state.metadata().get::<Tokens>().is_none() {
            state.add_metadata(Tokens::from_tokens_file(tokenfile)?);
        }
    }

    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    let tracing = ShadowTracingStage::new(&mut executor);

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(I2SRandReplace::new());

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

    let mut stages = tuple_list!(tracing, i2s, StdMutationalStage::new(mutator));

    // Remove target ouput (logs still survive)
    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        dup2(null_fd, io::stderr().as_raw_fd())?;
    }
    // reopen file to make sure we're at the end
    log.replace(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&logfile)?,
    );

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    // Never reached
    Ok(())
}
