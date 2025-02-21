//! A fuzzer using qemu in systemmode for binary-only coverage of kernels
use core::time::Duration;
use std::{env, path::PathBuf, process};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{CalibrationStage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Error,
};
use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_qemu::{
    breakpoint::Breakpoint,
    command::{EndCommand, StartCommand},
    elf::EasyElf,
    emu::Emulator,
    executor::QemuExecutor,
    modules::edges::StdEdgeCoverageModule,
    GuestPhysAddr, GuestReg, QemuMemoryChunk,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};

// use libafl_qemu::QemuSnapshotBuilder; // for normal qemu snapshot

pub static mut MAX_INPUT_SIZE: usize = 50;

pub fn fuzz() {
    env_logger::init();

    if let Ok(s) = env::var("FUZZ_SIZE") {
        str::parse::<usize>(&s).expect("FUZZ_SIZE was not a number");
    };
    // Hardcoded parameters
    let timeout = Duration::from_secs(3);
    let broker_port = 1337;
    let cores = Cores::from_cmdline("1").unwrap();
    let corpus_dirs = [PathBuf::from("./corpus")];
    let objective_dir = PathBuf::from("./crashes");

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(
        env::var("KERNEL").expect("KERNEL env not set"),
        &mut elf_buffer,
    )
    .unwrap();

    let input_addr = elf
        .resolve_symbol(
            &env::var("FUZZ_INPUT").unwrap_or_else(|_| "FUZZ_INPUT".to_owned()),
            0,
        )
        .expect("Symbol or env FUZZ_INPUT not found") as GuestPhysAddr;
    println!("FUZZ_INPUT @ {input_addr:#x}");

    let main_addr = elf
        .resolve_symbol("main", 0)
        .expect("Symbol main not found");
    println!("main address = {main_addr:#x}");

    let breakpoint = elf
        .resolve_symbol(
            &env::var("BREAKPOINT").unwrap_or_else(|_| "BREAKPOINT".to_owned()),
            0,
        )
        .expect("Symbol or env BREAKPOINT not found");
    println!("Breakpoint address = {breakpoint:#x}");

    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        let args: Vec<String> = env::args().collect();

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                           state: &mut _,
                           input: &BytesInput| unsafe {
            emulator.run(state, input).unwrap().try_into().unwrap()
        };

        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Initialize QEMU Emulator
        let emu = Emulator::builder()
            .qemu_parameters(args)
            .prepend_module(
                StdEdgeCoverageModule::builder()
                    .map_observer(edges_observer.as_mut())
                    .build()?,
            )
            .build()?;

        // Set breakpoints of interest with corresponding commands.
        emu.add_breakpoint(
            Breakpoint::with_command(
                main_addr,
                StartCommand::new(QemuMemoryChunk::phys(
                    input_addr,
                    unsafe { MAX_INPUT_SIZE } as GuestReg,
                    None,
                ))
                .into(),
                true,
            ),
            true,
        );
        emu.add_breakpoint(
            Breakpoint::with_command(
                breakpoint,
                EndCommand::new(Some(ExitKind::Ok)).into(),
                false,
            ),
            true,
        );

        let devices = emu.list_devices();
        println!("Devices = {:?}", devices);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
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
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let calibration_feedback = MaxMapFeedback::new(&edges_observer);
        let mut stages = tuple_list!(
            StdMutationalStage::new(mutator),
            CalibrationStage::new(&calibration_feedback)
        );

        // Create a QEMU in-process executor
        let mut executor = QemuExecutor::new(
            emu,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout,
        )
        .expect("Failed to create QemuExecutor");

        // Instead of calling the timeout handler and restart the process, trigger a breakpoint ASAP
        executor.break_on_timeout();

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .unwrap();
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // let monitor = SimpleMonitor::new(|s| println!("{s}"));
    // let mut mgr = SimpleEventManager::new(monitor);
    // run_client(None, mgr, 0);

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        // .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
