//! A fuzzer using qemu in systemmode for binary-only coverage of linux

use core::time::Duration;
use std::{env, path::PathBuf, process};

#[cfg(not(feature = "nyx"))]
use libafl::state::HasExecutions;
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{launcher::Launcher, EventConfig},
    executors::ShadowExecutor,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{havoc_mutations, scheduled::StdScheduledMutator, I2SRandReplaceBinonly},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{ShadowTracingStage, StdMutationalStage},
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
#[cfg(feature = "nyx")]
use libafl_qemu::{command::nyx::NyxCommandManager, NyxEmulatorDriver};
#[cfg(not(feature = "nyx"))]
use libafl_qemu::{
    command::StdCommandManager, modules::utils::filters::LINUX_PROCESS_ADDRESS_RANGE,
    StdEmulatorDriver,
};
use libafl_qemu::{
    emu::Emulator,
    executor::QemuExecutor,
    modules::{
        cmplog::CmpLogObserver, edges::StdEdgeCoverageClassicModule,
        utils::filters::HasAddressFilterTuple, CmpLogModule, EmulatorModuleTuple,
    },
    FastSnapshotManager, NopSnapshotManager, QemuInitError,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};

#[cfg(feature = "nyx")]
fn get_emulator<C, ET, I, S>(
    args: Vec<String>,
    modules: ET,
) -> Result<
    Emulator<C, NyxCommandManager<S>, NyxEmulatorDriver, ET, I, S, NopSnapshotManager>,
    QemuInitError,
>
where
    ET: EmulatorModuleTuple<I, S>,
    I: HasTargetBytes + Unpin,
    S: Unpin,
{
    Emulator::empty()
        .qemu_parameters(args)
        .modules(modules)
        .driver(NyxEmulatorDriver::builder().build())
        .command_manager(NyxCommandManager::default())
        .snapshot_manager(NopSnapshotManager::default())
        .build()
}

#[cfg(not(feature = "nyx"))]
fn get_emulator<C, ET, I, S>(
    args: Vec<String>,
    mut modules: ET,
) -> Result<
    Emulator<C, StdCommandManager<S>, StdEmulatorDriver, ET, I, S, FastSnapshotManager>,
    QemuInitError,
>
where
    ET: EmulatorModuleTuple<I, S> + HasAddressFilterTuple,
    I: HasTargetBytes + Unpin,
    S: HasExecutions + Unpin,
{
    // Allow linux process address space addresses as feedback
    modules.allow_address_range_all(&LINUX_PROCESS_ADDRESS_RANGE);

    Emulator::builder()
        .qemu_parameters(args)
        .modules(modules)
        .build()
}

#[allow(unused)]
fn display_args() {
    let args: Vec<String> = env::args().collect();

    let mut arg_str = String::new();
    for arg in args {
        arg_str.push_str(&arg);
        arg_str.push_str(" \\\n\t");
    }
    arg_str.pop();
    arg_str.pop();
    arg_str.pop();

    log::info!("QEMU args:");
    log::info!("\n{arg_str}");
}

pub fn fuzz() {
    env_logger::init();

    if let Ok(s) = env::var("FUZZ_SIZE") {
        str::parse::<usize>(&s).expect("FUZZ_SIZE was not a number");
    };
    // Hardcoded parameters
    let timeout = Duration::from_secs(60000);
    let broker_port = 1337;
    let cores = Cores::from_cmdline("1").unwrap();
    let corpus_dirs = [PathBuf::from("./corpus")];
    let objective_dir = PathBuf::from("./crashes");

    let mut run_client = |state: Option<_>, mut mgr, _client_description| {
        // Initialize QEMU
        let args: Vec<String> = env::args().collect();

        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        // Choose modules to use
        let modules = tuple_list!(
            StdEdgeCoverageClassicModule::builder()
                .map_observer(edges_observer.as_mut())
                .build()?,
            CmpLogModule::default(),
        );

        let emu = get_emulator(args, modules)?;

        let devices = emu.list_devices();
        println!("Devices = {:?}", devices);

        // The wrapped harness function, calling out to the LLVM-style harness
        let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                           state: &mut _,
                           input: &BytesInput| unsafe {
            emulator.run(state, input).unwrap().try_into().unwrap()
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Create a cmplog observer
        let cmplog_observer = CmpLogObserver::new("cmplog", true);

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
                InMemoryOnDiskCorpus::new("corpus_gen").unwrap(),
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

        let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        // a CmpLog-based mutational stage
        let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
            I2SRandReplaceBinonly::new()
        )));

        // Setup an havoc mutator with a mutational stage
        let tracing = ShadowTracingStage::new(&mut executor);
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(tracing, i2s, StdMutationalStage::new(mutator),);

        match fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr) {
            Ok(_) | Err(Error::ShuttingDown) => Ok(()),
            Err(e) => return Err(e),
        }
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
