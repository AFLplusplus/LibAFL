use std::path::PathBuf;
#[cfg(windows)]
use std::ptr::write_volatile;

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, DiffExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsIterableMapObserver, HitcountsMapObserver, StdMapObserver},
    prelude::{MultiMapObserver, OwnedSliceMut},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasSolutions, StdState},
};
use libafl_targets::{DifferentialAFLMapSwapObserver, EDGES_MAP_SIZE};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// bindings to the functions defined in the target
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

static mut FIRST_EDGES: [u8; EDGES_MAP_SIZE] = [0u8; EDGES_MAP_SIZE];
static mut SECOND_EDGES: [u8; EDGES_MAP_SIZE] = [0u8; EDGES_MAP_SIZE];
static mut COMBINED_EDGES: [&mut [u8]; 2] = unsafe { [&mut FIRST_EDGES, &mut SECOND_EDGES] };

#[allow(clippy::similar_names)]
pub fn main() {
    // The closure that we want to fuzz
    let mut first_harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        if unsafe { inspect_first(buf.as_ptr(), buf.len()) } {
            ExitKind::Crash
        } else {
            ExitKind::Ok
        }
    };
    let mut second_harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        if unsafe { inspect_second(buf.as_ptr(), buf.len()) } {
            ExitKind::Crash
        } else {
            ExitKind::Ok
        }
    };

    // create the base maps used to observe the different executors
    let mut first_map_observer = StdMapObserver::new("first-edges", unsafe { &mut FIRST_EDGES });
    let mut second_map_observer = StdMapObserver::new("second-edges", unsafe { &mut SECOND_EDGES });

    // create a map swapper so that we can replace the coverage map pointer (requires feature pointer_maps!)
    let mut map_swapper =
        DifferentialAFLMapSwapObserver::new(&mut first_map_observer, &mut second_map_observer);

    // create a multimap observer, e.g. for calibration
    let map_observer = HitcountsIterableMapObserver::new(MultiMapObserver::differential(
        "combined-edges",
        unsafe { &mut COMBINED_EDGES },
    ));

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&map_observer);

    // A feedback to choose if an input is a solution or not
    // Crash here means "both crashed", which is our objective
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
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
    #[cfg(not(feature = "tui"))]
    let mon = SimpleMonitor::new(|s| println!("{}", s));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::new(String::from("Baby Fuzzer"), false);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut first_executor = InProcessExecutor::new(
        &mut first_harness,
        tuple_list!(first_map_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the first executor");
    let mut second_executor = InProcessExecutor::new(
        &mut second_harness,
        tuple_list!(second_map_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the second executor");

    let mut differential_executor = DiffExecutor::new(
        first_executor,
        second_executor,
        tuple_list!(map_swapper, map_observer),
    );

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(
            &mut fuzzer,
            &mut differential_executor,
            &mut generator,
            &mut mgr,
            8,
        )
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    while state.solutions().is_empty() {
        fuzzer
            .fuzz_one(
                &mut stages,
                &mut differential_executor,
                &mut state,
                &mut mgr,
            )
            .expect("Error in the fuzzing loop");
    }
}
