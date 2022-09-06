//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
use core::time::Duration;
use std::{env, path::PathBuf, process};

use clap::{self, StructOpt};
use libafl::{
    bolts::{
        core_affinity::Cores,
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{Corpus, OnDiskCorpus},
    events::EventConfig,
    executors::{ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::{tui::TuiMonitor, MultiMonitor},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    Error,
};
use libafl_qemu::{
    //asan::QemuAsanHelper,
    edges,
    edges::QemuEdgeCoverageHelper,
    elf::EasyElf,
    emu::Emulator,
    GuestUsize,
    MmapPerms,
    QemuExecutor,
    QemuHooks,
    Regs,
};

/// The commandline args this fuzzer accepts
#[derive(Debug, StructOpt)]
#[clap(
    name = "qemu_arm_launcher",
    about = "A QEMU based fuzzer for libpng with a launcher"
)]
struct Opt {
    #[clap(
        short,
        long,
        parse(try_from_str = Cores::from_cmdline),
        help = "Spawn a client in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
        name = "CORES",
        default_value = "all"
    )]
    cores: Cores,

    #[clap(value_parser, required(false))]
    args: Vec<String>,

    #[clap(short, long)]
    tui: bool,

    #[clap(short, long)]
    verbose: bool,

    #[clap(short, long, value_parser, required(true))]
    input: Vec<String>,

    #[clap(short, long, value_parser, required(true))]
    output: String,
}

pub fn fuzz() {
    let mut opt = Opt::parse();

    // Hardcoded parameters
    let timeout = Duration::from_secs(1);
    let broker_port = 1337;
    let corpus_dirs = opt.input.iter().map(|x| PathBuf::from(x)).collect::<Vec<PathBuf>>();

    let objective_dir = PathBuf::from("./crashes");

    // Initialize QEMU
    env::remove_var("LD_LIBRARY_PATH");

    let argv0 = env::args().nth(0).unwrap();
    let mut args: Vec<String> = vec![argv0];
    args.append(&mut opt.args);

    let env: Vec<(String, String)> = env::vars().collect();
    let emu = Emulator::new(&args, &env);

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    println!("LLVMFuzzerTestOneInput @ {:#x}", test_one_input_ptr);

    emu.set_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    unsafe { emu.run() };

    println!("Break at {:#x}", emu.read_reg::<_, u64>(Regs::Pc).unwrap());

    // Get the return address
    let stack_ptr: u64 = emu.read_reg(Regs::Sp).unwrap();
    let ret_addr: u32 = emu.read_reg(Regs::Lr).unwrap();

    println!("Stack pointer = {:#x}", stack_ptr);
    println!("Return address = {:#x}", ret_addr);

    emu.remove_breakpoint(test_one_input_ptr); // LLVMFuzzerTestOneInput
    emu.set_breakpoint(ret_addr); // LLVMFuzzerTestOneInput ret addr

    let input_addr = emu.map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
    println!("Placing input at {:#x}", input_addr);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > 4096 {
            buf = &buf[0..4096];
            len = 4096;
        }

        unsafe {
            emu.write_mem(input_addr, buf);

            emu.write_reg(Regs::R0, input_addr).unwrap();
            emu.write_reg(Regs::R1, len as GuestUsize).unwrap();
            emu.write_reg(Regs::Pc, test_one_input_ptr).unwrap();
            emu.write_reg(Regs::Lr, ret_addr).unwrap();

            emu.run();
        }

        ExitKind::Ok
    };

    let mut run_client = |state: Option<_>, mut mgr, _core_id| {
        // Create an observation channel using the coverage map
        let edges = unsafe { &mut edges::EDGES_MAP };
        let edges_counter = unsafe { &mut edges::MAX_EDGES_NUM };
        let edges_observer =
            HitcountsMapObserver::new(VariableMapObserver::new("edges", edges, edges_counter));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new_tracking(&edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                OnDiskCorpus::new(opt.output.clone()).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut hooks = QemuHooks::new(&emu, tuple_list!(QemuEdgeCoverageHelper::default()));

        // Create a QEMU in-process executor
        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create QemuExecutor");

        // Wrap the executor to keep track of the timeout
        let mut executor = TimeoutExecutor::new(executor, timeout);

        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    let output = if opt.verbose { Some("/dev/stdout") } else { Some ("/dev/null")};

    match if opt.tui {
        Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(broker_port)
            .configuration(EventConfig::from_build_id())
            .monitor(TuiMonitor::new(String::from("QEMU Arm Launcher"), false))
            .run_client(&mut run_client)
            .cores(&opt.cores)
            .stdout_file(output)
            .build()
            .launch()
    } else {
        Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(broker_port)
            .configuration(EventConfig::from_build_id())
            .monitor(MultiMonitor::new(|s| println!("{}", s)))
            .run_client(&mut run_client)
            .cores(&opt.cores)
            .stdout_file(output)
            .build()
            .launch()
    } {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}
