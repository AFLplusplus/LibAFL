//! A fuzzer using qemu in systemmode with intel PT

use core::time::Duration;
use std::{
    env,
    num::NonZero,
    ops::RangeInclusive,
    path::{Path, PathBuf},
};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{ProgressReporter, SimpleEventManager},
    executors::ExitKind,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::{StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::{HasSolutions, StdState},
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice};
use libafl_qemu::{
    config,
    config::{Accelerator, DriveCache, QemuConfig},
    executor::QemuExecutor,
    modules::intel_pt::{IntelPTModule, Section},
    Emulator, EmulatorBuilder, GuestAddr, QemuExitReason, QemuShutdownCause,
};

// Coverage map
const MAP_SIZE: usize = 256;
static mut MAP: [u16; MAP_SIZE] = [0; MAP_SIZE];

// Bootloader code section and sleep fn address can be retrieved with `ndisasm target/boot.bin`
const BOOTLOADER_CODE: RangeInclusive<usize> = 0x7c00..=0x7c80;
const BOOTLOADER_SLEEP_FN_ADDR: GuestAddr = 0x7c60;

fn main() {
    // Initialize the logger (use env variable RUST_LOG=trace for maximum logging)
    env_logger::init();

    // Hardcoded parameters
    let timeout = Duration::from_secs(5);
    let objective_dir = PathBuf::from("./crashes");

    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    let target_dir = env::var("TARGET_DIR").unwrap_or("target".to_string());

    // Configure QEMU
    let qemu_config = QemuConfig::builder()
        .no_graphic(true)
        .monitor(config::Monitor::Null)
        .serial(config::Serial::Null)
        .cpu("host")
        .ram_size(config::RamSize::MB(1))
        .drives([config::Drive::builder()
            .format(config::DiskImageFileFormat::Qcow2)
            .file("/mnt/libafl_qemu_tmpfs/boot.qcow2")
            .cache(DriveCache::None)
            .build()])
        .accelerator(Accelerator::Kvm)
        //.snapshot(true) todo: doesnt work
        .default_devices(false)
        .bios("/home/marco/code/qemu-libafl-bridge/build/qemu-bundle/usr/local/share/qemu/")
        .start_cpu(false)
        .build();

    let file_path = Path::new(&target_dir)
        .join("boot.bin")
        .to_string_lossy()
        .to_string();
    let image = [Section {
        file_path,
        file_offset: 0,
        size: (BOOTLOADER_CODE.end() - BOOTLOADER_CODE.start()) as u64 + 1,
        virtual_address: *BOOTLOADER_CODE.start() as u64,
    }];
    let intel_pt_builder = IntelPTModule::default_pt_builder().ip_filters(&[BOOTLOADER_CODE]);
    let emulator_modules = tuple_list!(IntelPTModule::builder()
        .map_ptr(unsafe { MAP.as_mut_ptr() })
        .map_len(MAP_SIZE)
        .intel_pt_builder(intel_pt_builder)
        .image(&image)
        .build());

    let emulator = EmulatorBuilder::empty()
        .qemu_parameters(qemu_config)
        .modules(emulator_modules)
        .build()
        .unwrap();
    let qemu = emulator.qemu();
    qemu.set_hw_breakpoint(*BOOTLOADER_CODE.start() as GuestAddr)
        .unwrap();

    // todo: there is smth broken somewhere, QemuExitReason::Breakpoint reports a wrong address
    unsafe {
        match qemu.run() {
            Ok(QemuExitReason::Breakpoint(ba)) => {
                println!("break1 at {ba:x}")
            }
            _ => panic!("Pre-harness Unexpected QEMU exit."),
        }
    }
    qemu.remove_hw_breakpoint(*BOOTLOADER_CODE.start() as GuestAddr)
        .unwrap();

    qemu.set_hw_breakpoint(BOOTLOADER_SLEEP_FN_ADDR).unwrap();

    qemu.save_snapshot("bootloader_start", true);

    let mut harness = |emulator: &mut Emulator<_, _, _, _, _, _, _>,
                       _: &mut StdState<_, _, _, _>,
                       input: &BytesInput| unsafe {
        let mut fixed_len_input = input.target_bytes().as_slice().to_vec();
        fixed_len_input.resize(3, 0);

        qemu.load_snapshot("bootloader_start", true);
        qemu.write_phys_mem(0xfe6f7, &fixed_len_input);
        match emulator.qemu().run() {
            Ok(QemuExitReason::End(QemuShutdownCause::GuestShutdown)) => {
                println!(
                    "crashing input: {}",
                    String::from_utf8_lossy(&fixed_len_input)
                );
                ExitKind::Crash
            }
            Ok(QemuExitReason::Breakpoint(_)) => ExitKind::Ok,
            e => panic!("Harness Unexpected QEMU exit. {e:?}"),
        }
    };

    // Create an observation channel using the map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", MAP.as_mut_ptr(), MAP_SIZE) };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new());

    // If not restarting, create a State from scratch
    let mut state = StdState::new(
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
    .unwrap();

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create a QEMU in-process executor
    let mut executor = QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )
    .expect("Failed to create QemuExecutor");

    // Generator of printable bytearrays of max size 3
    let mut generator = RandPrintablesGenerator::new(NonZero::new(3).unwrap());

    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 4)
        .expect("Failed to generate the initial corpus");

    // Setup an havoc mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    while state.solutions().is_empty() {
        mgr.maybe_report_progress(&mut state, Duration::from_secs(5))
            .unwrap();

        fuzzer
            .fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");
    }
}
