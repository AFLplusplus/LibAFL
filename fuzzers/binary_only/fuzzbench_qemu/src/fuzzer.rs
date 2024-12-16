//! A singlethreaded QEMU fuzzer that can auto-restart.

use core::{cell::RefCell, time::Duration};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    process,
};

use clap::{Arg, Command};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::SimpleRestartingEventManager,
    executors::{ExitKind, ShadowExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations, StdMOptMutator,
        StdScheduledMutator, Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, ShadowTracingStage,
        StdMutationalStage,
    },
    state::{HasCorpus, StdState},
    Error, HasMetadata,
};
use libafl_bolts::{
    current_time,
    os::dup2,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice,
};
use libafl_qemu::{
    elf::EasyElf,
    filter_qemu_args,
    // asan::{init_with_asan, QemuAsanHelper},
    modules::cmplog::{CmpLogModule, CmpLogObserver},
    modules::edges::StdEdgeCoverageModule,
    Emulator,
    GuestReg,
    //snapshot::QemuSnapshotHelper,
    MmapPerms,
    Qemu,
    QemuExecutor,
    QemuExitError,
    QemuExitReason,
    QemuShutdownCause,
    Regs,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_ALLOCATED_SIZE, MAX_EDGES_FOUND};
#[cfg(unix)]
use nix::unistd::dup;

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

/// The fuzzer main
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer with QEMU for Fuzzbench")
        .arg(
            Arg::new("out")
                .help("The directory to place finds in ('corpus')")
                .long("libafl-out")
                .required(true),
        )
        .arg(
            Arg::new("in")
                .help("The directory to read initial inputs from ('seeds')")
                .long("libafl-in")
                .required(true),
        )
        .arg(
            Arg::new("tokens")
                .long("libafl-tokens")
                .help("A file to read tokens from, to be used during fuzzing"),
        )
        .arg(
            Arg::new("logfile")
                .long("libafl-logfile")
                .help("Duplicates all output to this file")
                .default_value("libafl.log"),
        )
        .arg(
            Arg::new("timeout")
                .long("libafl-timeout")
                .help("Timeout for each individual execution, in milliseconds")
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
                err,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(res.get_one::<String>("out").unwrap().to_string());
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

    let in_dir = PathBuf::from(res.get_one::<String>("in").unwrap().to_string());
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let tokens = res.get_one::<String>("tokens").map(PathBuf::from);

    let logfile = PathBuf::from(res.get_one::<String>("logfile").unwrap().to_string());

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
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
    env_logger::init();
    env::remove_var("LD_LIBRARY_PATH");

    let args: Vec<String> = env::args().collect();
    let qemu = Qemu::init(&args).expect("QEMU init failed");
    // let (emu, asan) = init_with_asan(&mut args, &mut env).unwrap();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    println!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    qemu.set_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::Breakpoint(_)) => {}
            _ => panic!("Unexpected QEMU exit."),
        }
    }

    println!("Break at {:#x}", qemu.read_reg(Regs::Pc).unwrap());

    let stack_ptr: u64 = qemu.read_reg(Regs::Sp).unwrap();
    let mut ret_addr = [0; 8];

    qemu.read_mem(stack_ptr, &mut ret_addr)
        .expect("Error while reading QEMU memory.");

    let ret_addr = u64::from_le_bytes(ret_addr);

    println!("Stack pointer = {stack_ptr:#x}");
    println!("Return address = {ret_addr:#x}");

    qemu.remove_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    qemu.set_breakpoint(ret_addr); // LLVMFuzzerTestOneInput ret addr

    let input_addr = qemu
        .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
        .unwrap();
    println!("Placing input at {input_addr:#x}");

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
        writeln!(&mut stdout_cpy, "{s}").unwrap();
        #[cfg(windows)]
        println!("{s}");
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
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };

    // Create an observation channel using the coverage map
    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_ALLOCATED_SIZE),
            &raw mut MAX_EDGES_FOUND,
        ))
        .track_indices()
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Create an observation channel using cmplog map
    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let map_feedback = MaxMapFeedback::new(&edges_observer);

    let calibration = CalibrationStage::new(&map_feedback);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::new(),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
        StdPowerMutationalStage::new(mutator);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
    );

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness =
        |_emulator: &mut Emulator<_, _, _, _, _>, _state: &mut _, input: &BytesInput| {
            let target = input.target_bytes();
            let mut buf = target.as_slice();
            let mut len = buf.len();
            if len > MAX_INPUT_SIZE {
                buf = &buf[0..MAX_INPUT_SIZE];
                len = MAX_INPUT_SIZE;
            }

            unsafe {
                // # Safety
                // The input buffer size is checked above. We use `write_mem_unchecked` for performance reasons
                // For better error handling, use `write_mem` and handle the returned Result
                qemu.write_mem_unchecked(input_addr, buf);

                qemu.write_reg(Regs::Rdi, input_addr).unwrap();
                qemu.write_reg(Regs::Rsi, len as GuestReg).unwrap();
                qemu.write_reg(Regs::Rip, test_one_input_ptr).unwrap();
                qemu.write_reg(Regs::Rsp, stack_ptr).unwrap();

                match qemu.run() {
                    Ok(QemuExitReason::Breakpoint(_)) => {}
                    Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                        signal.handle();
                    }
                    Err(QemuExitError::UnexpectedExit) => return ExitKind::Crash,
                    _ => panic!("Unexpected QEMU exit."),
                }
            }

            ExitKind::Ok
        };

    let modules = tuple_list!(
        StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()
            .unwrap(),
        CmpLogModule::default(),
        // QemuAsanHelper::default(asan),
        //QemuSnapshotHelper::new()
    );

    let emulator = Emulator::empty().qemu(qemu).modules(modules).build()?;

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let executor = QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    // Show the cmplog observer
    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    // Read tokens
    if let Some(tokenfile) = tokenfile {
        if state.metadata_map().get::<Tokens>().is_none() {
            state.add_metadata(Tokens::from_file(tokenfile)?);
        }
    }

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} input(s) from disk.", state.corpus().count());
    }

    let tracing = ShadowTracingStage::new(&mut executor);

    // The order of the stages matter!
    let mut stages = tuple_list!(calibration, tracing, i2s, power);

    // Remove target output (logs still survive)
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
