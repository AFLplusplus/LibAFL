use std::{
    env, ffi::CString, num::NonZero, os::unix::ffi::OsStrExt, path::PathBuf, time::Duration,
};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        command::{CommandConfigurator, PTraceCommandConfigurator},
        hooks::intel_pt::{IntelPTHook, SectionInfo},
    },
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{core_affinity, rands::StdRand, tuples::tuple_list};
use libafl_intelpt::{IntelPT, PAGE_SIZE};

// Coverage map
const MAP_SIZE: usize = 4096;
static mut MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];
// TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
#[allow(static_mut_refs)] // only a problem in nightly
static mut MAP_PTR: *mut u8 = unsafe { MAP.as_mut_ptr() };

pub fn main() {
    // Let's set the default logging level to `warn`
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "warn")
    }
    // Enable logging
    env_logger::init();

    // path of the program we want to fuzz
    let target_path = PathBuf::from(env::args().next().unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target_program");

    // We'll run the target on cpu (aka core) 0
    let cpu = core_affinity::get_core_ids().unwrap()[0];
    log::debug!("Using core {} for fuzzing", cpu.0);

    // Create an observation channel using the map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", MAP_PTR, MAP_SIZE) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The target is a ET_DYN elf, it will be relocated by the loader with this offset.
    // see https://github.com/torvalds/linux/blob/c1e939a21eb111a6d6067b38e8e04b8809b64c4e/arch/x86/include/asm/elf.h#L234C1-L239C38
    const DEFAULT_MAP_WINDOW: usize = (1 << 47) - PAGE_SIZE;
    const ELF_ET_DYN_BASE: usize = (DEFAULT_MAP_WINDOW / 3 * 2) & !(PAGE_SIZE - 1);

    // Set the instruction pointer (IP) filter and memory image of our target.
    // These information can be retrieved from `readelf -l` (for example)
    let code_memory_addresses = ELF_ET_DYN_BASE + 0x15000..=ELF_ET_DYN_BASE + 0x14000 + 0x41000;

    let intel_pt = IntelPT::builder()
        .cpu(cpu.0)
        .inherit(true)
        .ip_filters(&[code_memory_addresses.clone()])
        .build()
        .unwrap();

    let sections = [SectionInfo {
        filename: target_path.to_string_lossy().to_string(),
        offset: 0x14000,
        size: (*code_memory_addresses.end() - *code_memory_addresses.start() + 1) as u64,
        virtual_address: *code_memory_addresses.start() as u64,
    }];

    let hook = unsafe { IntelPTHook::builder().map_ptr(MAP_PTR).map_len(MAP_SIZE) }
        .intel_pt(intel_pt)
        .image(&sections)
        .build();

    let target_cstring = CString::from(
        target_path
            .as_os_str()
            .as_bytes()
            .iter()
            .map(|&b| NonZero::new(b).unwrap())
            .collect::<Vec<_>>(),
    );

    let command_configurator = PTraceCommandConfigurator::builder()
        .path(target_cstring)
        .cpu(cpu)
        .timeout(Duration::from_secs(2))
        .build();
    let mut executor =
        <PTraceCommandConfigurator as CommandConfigurator<BytesInput, _>>::into_executor_with_hooks(
            command_configurator,
            tuple_list!(observer),
            tuple_list!(hook),
        );

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(NonZero::new(32).unwrap());

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
