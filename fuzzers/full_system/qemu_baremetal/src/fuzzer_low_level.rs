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
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::StdMutationalStage,
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
    AsSlice,
};
use libafl_qemu::{
    config, config::QemuConfig, elf::EasyElf, executor::QemuExecutor,
    modules::edges::StdEdgeCoverageModuleBuilder, Emulator, GuestPhysAddr, QemuExitError,
    QemuExitReason, QemuRWError, QemuShutdownCause, Regs,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};

pub static mut MAX_INPUT_SIZE: usize = 50;

#[allow(clippy::too_many_lines)]
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

    let input_addr = GuestPhysAddr::from(
        elf.resolve_symbol(
            &env::var("FUZZ_INPUT").unwrap_or_else(|_| "FUZZ_INPUT".to_owned()),
            0,
        )
        .expect("Symbol or env FUZZ_INPUT not found"),
    );
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
        let target_dir = env::var("TARGET_DIR").expect("TARGET_DIR env not set");

        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        // Create QEMU configuration
        let qemu_config = QemuConfig::builder()
            .machine("mps2-an385")
            .monitor(config::Monitor::Null)
            .kernel(format!("{target_dir}/example.elf"))
            .serial(config::Serial::Null)
            .no_graphic(true)
            .snapshot(true)
            .drives([config::Drive::builder()
                .interface(config::DriveInterface::None)
                .format(config::DiskImageFileFormat::Qcow2)
                .file(format!("{target_dir}/dummy.qcow2"))
                .build()])
            .start_cpu(false)
            .build();

        let emulator_modules = tuple_list!(StdEdgeCoverageModuleBuilder::default()
            .map_observer(edges_observer.as_mut())
            .build()?);

        let emulator = Emulator::empty()
            .qemu_parameters(qemu_config)
            .modules(emulator_modules)
            .build()?;

        let qemu = emulator.qemu();

        qemu.set_breakpoint(main_addr);

        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {}
                _ => panic!("Unexpected QEMU exit."),
            }
        }

        qemu.remove_breakpoint(main_addr);

        qemu.set_breakpoint(breakpoint); // BREAKPOINT

        let devices = qemu.list_devices();
        println!("Devices = {devices:?}");

        // let saved_cpu_states: Vec<_> = (0..emu.num_cpus())
        //     .map(|i| emu.cpu_from_index(i).save_state())
        //     .collect();

        // emu.save_snapshot("start", true);

        let snap = qemu.create_fast_snapshot(true);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness =
            |emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut _, input: &BytesInput| {
                let target = input.target_bytes();
                let mut buf = target.as_slice();
                let len = buf.len();
                unsafe {
                    if len > MAX_INPUT_SIZE {
                        buf = &buf[0..MAX_INPUT_SIZE];
                        // len = MAX_INPUT_SIZE;
                    }

                    qemu.write_phys_mem(input_addr, buf);

                    match emulator.qemu().run() {
                        Ok(QemuExitReason::Breakpoint(_)) => {} // continue execution, nothing to do there.
                        Ok(QemuExitReason::Timeout) => return ExitKind::Timeout, // timeout, propagate
                        Ok(QemuExitReason::End(QemuShutdownCause::HostSignal(signal))) => {
                            // will take care of cleanly stopping the fuzzer.
                            signal.handle()
                        }

                        Err(QemuExitError::UnexpectedExit) => return ExitKind::Crash,
                        e => panic!("Unexpected QEMU exit: {e:?}."),
                    }

                    // If the execution stops at any point other than the designated breakpoint (e.g. a breakpoint on a panic method) we consider it a crash
                    let mut pcs = (0..qemu.num_cpus())
                        .map(|i| qemu.cpu_from_index(i))
                        .map(|cpu| -> Result<u32, QemuRWError> { cpu.read_reg(Regs::Pc) });
                    let ret = match pcs
                        .find(|pc| (breakpoint..breakpoint + 5).contains(pc.as_ref().unwrap_or(&0)))
                    {
                        Some(_) => ExitKind::Ok,
                        None => ExitKind::Crash,
                    };

                    // OPTION 1: restore only the CPU state (registers et. al)
                    // for (i, s) in saved_cpu_states.iter().enumerate() {
                    //     emu.cpu_from_index(i).restore_state(s);
                    // }

                    // OPTION 2: restore a slow vanilla QEMU snapshot
                    // emu.load_snapshot("start", true);

                    // OPTION 3: restore a fast devices+mem snapshot
                    qemu.restore_fast_snapshot(snap);

                    ret
                }
            };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

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

        // Create a QEMU in-process executor
        let mut executor = QemuExecutor::new(
            emulator,
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

        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

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
