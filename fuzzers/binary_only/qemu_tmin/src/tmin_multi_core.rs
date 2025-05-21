//! A binary-only testcase minimizer using qemu, similar to AFL++ afl-tmin
#[cfg(feature = "i386")]
use core::mem::size_of;
use core::str::from_utf8;
#[cfg(feature = "snapshot")]
use core::time::Duration;
use std::{env, fmt::Write, io, path::PathBuf, process, ptr::NonNull};

use clap::{builder::Str, Parser};
use libafl::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId, InMemoryCorpus, InMemoryOnDiskCorpus},
    events::{
        launcher::Launcher, ClientDescription, EventConfig, LlmpRestartingEventManager, SendExiting,
    },
    executors::ExitKind,
    feedbacks::MaxMapFeedback,
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{havoc_mutations, HavocScheduledMutator},
    observers::{ConstMapObserver, HitcountsMapObserver},
    schedulers::QueueScheduler,
    stages::{ObserverEqualityFactory, StagesTuple, StdTMinMutationalStage},
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    os::unix_signals::Signal,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice, AsSliceMut,
};
use libafl_qemu::{
    elf::EasyElf,
    modules::{edges::StdEdgeCoverageChildModule, RedirectStdoutModule},
    ArchExtras, Emulator, GuestAddr, GuestReg, MmapPerms, QemuExitError, QemuExitReason,
    QemuShutdownCause, Regs,
};
#[cfg(feature = "snapshot")]
use libafl_qemu::{modules::SnapshotModule, QemuExecutor};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, EDGES_MAP_PTR};

#[cfg(feature = "fork")]
compile_error!("'fork' feature is currently not implemented; pending forkserver PR.");

#[cfg(all(feature = "fork", feature = "snapshot"))]
compile_error!("Cannot enable both 'fork' and 'snapshot' features at the same time.");

#[derive(Default)]
pub struct Version;

impl From<Version> for Str {
    fn from(_: Version) -> Str {
        let version = [
            ("Architecture:", env!("CPU_TARGET")),
            ("Build Timestamp:", env!("VERGEN_BUILD_TIMESTAMP")),
            ("Describe:", env!("VERGEN_GIT_DESCRIBE")),
            ("Commit SHA:", env!("VERGEN_GIT_SHA")),
            ("Commit Date:", env!("VERGEN_RUSTC_COMMIT_DATE")),
            ("Commit Branch:", env!("VERGEN_GIT_BRANCH")),
            ("Rustc Version:", env!("VERGEN_RUSTC_SEMVER")),
            ("Rustc Channel:", env!("VERGEN_RUSTC_CHANNEL")),
            ("Rustc Host Triple:", env!("VERGEN_RUSTC_HOST_TRIPLE")),
            ("Rustc Commit SHA:", env!("VERGEN_RUSTC_COMMIT_HASH")),
            ("Cargo Target Triple", env!("VERGEN_CARGO_TARGET_TRIPLE")),
        ]
        .iter()
        .fold(String::new(), |mut output, (k, v)| {
            let _ = writeln!(output, "{k:25}: {v}");
            output
        });

        format!("\n{version:}").into()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
name = format ! ("qemu_tmin-{}", env ! ("CPU_TARGET")),
version = Version::default(),
about,
long_about = "Module for minimizing test cases using QEMU instrumentation"
)]
pub struct FuzzerOptions {
    #[arg(long, help = "Output directory")]
    output: String,

    #[arg(long, help = "Input directory")]
    input: String,

    #[arg(long, help = "Timeout in seconds", default_value_t = 1_u64)]
    timeout: u64,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    cores: Cores,

    #[arg(
        long,
        help = "Number of iterations for minimization",
        default_value_t = 1024_usize
    )]
    iterations: usize,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

pub const MAX_INPUT_SIZE: usize = 1048576; // 1MB

pub fn fuzz() {
    // Initialise env_logger
    env_logger::init();

    // Parse user options
    let mut options = FuzzerOptions::parse();
    let program = env::args().next().unwrap();
    log::info!("Program: {program:}");
    options.args.insert(0, program);
    log::info!("ARGS: {:#?}", options.args);

    // Get all of the files supplied from the input corpus
    let corpus_dir = PathBuf::from(options.input);
    let files = corpus_dir
        .read_dir()
        .expect("Failed to read corpus dir")
        .map(|x| Ok(x?.path()))
        .collect::<Result<Vec<PathBuf>, io::Error>>()
        .expect("Failed to read dir entry");

    // To run parallelised, we work out number of files to process per core.
    let num_files = files.len();
    let num_cores = options.cores.ids.len();
    let files_per_core = (num_files as f64 / num_cores as f64).ceil() as usize;

    // Create a shared memory region for sharing coverage map between fuzzer and target
    // In snapshot mode, this is only required for the SimpleRestartingEventManager.
    // However, fork mode requires it to share memory between parent and child,
    // so we use it in both cases.
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // Clear LD_LIBRARY_PATH
    env::remove_var("LD_LIBRARY_PATH");

    // The client closure is a 'fuzzing' process for a single core.
    // Because it is used inside the Launcher (below) it is a fork()ed separate
    // process from our main process here.
    let mut run_client = |state: Option<_>,
                          mut mgr: LlmpRestartingEventManager<_, _, _, _, _>,
                          client_description: ClientDescription| {
        let core_id = client_description.core_id();
        let core_idx = options
            .cores
            .position(core_id)
            .expect("Failed to get core index");

        let files: Vec<PathBuf> = files
            .iter()
            .skip(files_per_core * core_idx)
            .take(files_per_core)
            .cloned()
            .collect::<Vec<PathBuf>>();

        if files.is_empty() {
            mgr.send_exiting()?;
            Err(Error::ShuttingDown)?
        }

        let mut edges_shmem = shmem_provider
            .clone()
            .new_shmem(EDGES_MAP_DEFAULT_SIZE)
            .unwrap();
        let edges = edges_shmem.as_slice_mut();
        unsafe { EDGES_MAP_PTR = edges.as_mut_ptr() };

        // We use a HitcountsMapObserver to observe the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(ConstMapObserver::from_mut_ptr(
                "edges",
                NonNull::new(edges.as_mut_ptr())
                    .expect("The edge map pointer is null.")
                    .cast::<[u8; EDGES_MAP_DEFAULT_SIZE]>(),
            ))
        };

        let stdout_callback = |buf: &[u8]| {
            if let Ok(s) = from_utf8(buf) {
                let msg = s.trim_end();
                if msg.len() != 0 {
                    log::info!("{msg}");
                }
            }
        };

        let redirect_stdout_module = if options.verbose {
            RedirectStdoutModule::new()
                .with_stderr(stdout_callback)
                .with_stdout(stdout_callback)
        } else {
            RedirectStdoutModule::new()
        };

        // In either fork/snapshot mode, we link the observer to QEMU
        #[cfg(feature = "snapshot")]
        let modules = tuple_list!(
            StdEdgeCoverageChildModule::builder()
                .const_map_observer(edges_observer.as_mut())
                .build()?,
            SnapshotModule::new(),
            redirect_stdout_module
        );

        // Create our QEMU emulator
        let emulator = Emulator::empty()
            .qemu_parameters(options.args.clone())
            .modules(modules)
            .build()?;
        let qemu = emulator.qemu();

        // Use ELF tools to get the target function
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer).unwrap();
        let test_one_input_ptr = elf
            .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
            .expect("Symbol LLVMFuzzerTestOneInput not found");
        log::info!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

        // Run target until the target function, and store important registers.
        // Set a breakpoint on target function return.
        qemu.entry_break(test_one_input_ptr);
        let stack_ptr: GuestAddr = qemu.read_reg(Regs::Sp).unwrap();
        let ret_addr: GuestAddr = qemu.read_return_address().unwrap();
        let pc: GuestReg = qemu.read_reg(Regs::Pc).unwrap();
        log::info!("Break at {pc:#x}");
        log::info!("Return address = {ret_addr:#x}");
        qemu.set_breakpoint(ret_addr);

        // Map a private region for input buffer
        let input_addr = qemu
            .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
            .unwrap();
        log::info!("Placing input at {input_addr:#x}");

        // Rust harness: this closure copies an input buffer to our private region
        // for target function input and updates registers to a single iteration
        // before telling QEMU to resume execution.
        #[cfg(feature = "snapshot")]
        let mut harness =
            |_emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput| {
                let target = input.target_bytes();
                let mut buf = target.as_slice();
                let mut len = buf.len();
                if len > MAX_INPUT_SIZE {
                    buf = &buf[0..MAX_INPUT_SIZE];
                    len = MAX_INPUT_SIZE;
                }
                let len = len as GuestReg;

                unsafe {
                    qemu.write_mem(input_addr, buf).expect("qemu write failed.");

                    qemu.write_reg(Regs::Pc, test_one_input_ptr).unwrap();
                    qemu.write_reg(Regs::Sp, stack_ptr).unwrap();
                    qemu.write_return_address(ret_addr).unwrap();
                    qemu.write_function_argument(0, input_addr).unwrap();
                    qemu.write_function_argument(1, len).unwrap();

                    match qemu.run() {
                        Ok(QemuExitReason::Breakpoint(_)) => {}
                        Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(
                            Signal::SigInterrupt,
                        ))) => process::exit(0),
                        Err(QemuExitError::UnexpectedExit) => return ExitKind::Crash,
                        _ => panic!("Unexpected QEMU exit."),
                    }
                }

                ExitKind::Ok
            };

        // Our fuzzer is a simple queue scheduler (FIFO), and has no corpus feedback
        // or objective feedback. This is important as we need the MaxMapFeedback
        // on the observer to be constrained by ObserverEqualityFactory which will
        // ensure interestingness is only true for identical coverage.
        let scheduler = QueueScheduler::new();
        let mut fuzzer = StdFuzzer::new(scheduler, (), ());

        // We define the stages that will be performed by the fuzzer. We have one
        // stage of the StdTMinMutationalStage which will run for n iterations.
        // The havoc mutator will generate mutations; only those shorter than the
        // current input will be tested; and the ObservreEqualityFactory will
        // provide an observer that ensures additions to the corpus have the same
        // coverage.
        let minimizer = HavocScheduledMutator::new(havoc_mutations());
        let factory = ObserverEqualityFactory::new(&edges_observer);
        let mut stages = tuple_list!(StdTMinMutationalStage::new(
            minimizer,
            factory,
            options.iterations
        ),);

        // Create a state instance. Unlike a typical fuzzer, we start with an empty
        // input corpus, and we don't care about 'solutions' so store in an
        // InMemoryCorpus.
        let mut feedback = MaxMapFeedback::new(&edges_observer);
        let mut objective = ();
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::new(),
                InMemoryOnDiskCorpus::new(PathBuf::from(options.output.clone())).unwrap(),
                InMemoryCorpus::new(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        // The executor. Nothing exciting here.
        #[cfg(feature = "snapshot")]
        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            tuple_list!(edges_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            Duration::from_millis(5000),
        )?;

        // Load the input corpus
        state.load_initial_inputs_by_filenames_forced(
            &mut fuzzer,
            &mut executor,
            &mut mgr,
            &files,
        )?;
        log::info!("Processed {} inputs from disk.", files.len());

        // Iterate over initial corpus_ids and minimize each.
        let corpus_ids: Vec<CorpusId> = state.corpus().ids().collect();
        for corpus_id in corpus_ids {
            state.set_corpus_id(corpus_id)?;
            stages.perform_all(&mut fuzzer, &mut executor, &mut state, &mut mgr)?;
        }

        mgr.send_exiting()?;
        Ok(())
    };

    // The Launcher creates forks on the specified list of cores, and for each
    // one runs the run_client closure which performs the work.
    // It links the forks to a MultiMonitor which just prints out the events
    // it receives.
    match Launcher::builder()
        .shmem_provider(shmem_provider.clone())
        .broker_port(options.port)
        .configuration(EventConfig::from_build_id())
        .monitor(MultiMonitor::new(|s| log::info!("{s}")))
        .run_client(&mut run_client)
        .cores(&options.cores)
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => {
            println!("Run finished successfully.");
        }
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }

    // Here it would be nice to sum the number of cases processed by each fork
    // to provide an exit summary (as is done for the "snapshot" version), but
    // to do so would require more communication between child and parent. So
    // it is left undone.
}

#[cfg(target_os = "linux")]
pub fn main() {
    fuzz();
}

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("qemu-user and libafl_qemu is only supported on linux!");
}
