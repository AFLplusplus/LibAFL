#[cfg(windows)]
use std::ptr::write_volatile;
use std::{
    alloc::{alloc_zeroed, Layout},
    path::PathBuf,
};

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
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasSolutions, StdState},
};
use libafl_targets::{DifferentialAFLMapSwapObserver, MAX_EDGES_NUM};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// bindings to the functions defined in the target
mod bindings {
    #![allow(non_snake_case)]
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]
    #![allow(clippy::unreadable_literal)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bindings::{inspect_first, inspect_second};

#[cfg(feature = "multimap")]
mod multimap {
    pub use libafl::observers::{HitcountsIterableMapObserver, MultiMapObserver};

    pub static mut FIRST_EDGES: &mut [u8] = &mut [];
    pub static mut SECOND_EDGES: &mut [u8] = &mut [];
    pub static mut COMBINED_EDGES: [&mut [u8]; 2] = [&mut [], &mut []];
}
#[cfg(feature = "multimap")]
use multimap::{
    HitcountsIterableMapObserver, MultiMapObserver, COMBINED_EDGES, FIRST_EDGES, SECOND_EDGES,
};

#[cfg(not(feature = "multimap"))]
mod slicemap {
    pub use libafl::observers::HitcountsMapObserver;

    pub static mut EDGES: &mut [u8] = &mut [];
}
#[cfg(not(feature = "multimap"))]
use slicemap::{HitcountsMapObserver, EDGES};

#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines)]
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

    #[cfg(feature = "multimap")]
    let (first_map_observer, second_map_observer, map_swapper, map_observer) = {
        // initialize the maps
        unsafe {
            let layout = Layout::from_size_align(MAX_EDGES_NUM, 64).unwrap();
            FIRST_EDGES = core::slice::from_raw_parts_mut(alloc_zeroed(layout), MAX_EDGES_NUM);
            SECOND_EDGES = core::slice::from_raw_parts_mut(alloc_zeroed(layout), MAX_EDGES_NUM);
            COMBINED_EDGES = [&mut FIRST_EDGES, &mut SECOND_EDGES];
        }

        // create the base maps used to observe the different executors from two independent maps
        let mut first_map_observer = unsafe { StdMapObserver::new("first-edges", FIRST_EDGES) };
        let mut second_map_observer = unsafe { StdMapObserver::new("second-edges", SECOND_EDGES) };

        // create a map swapper so that we can replace the coverage map pointer (requires feature pointer_maps!)
        let map_swapper =
            DifferentialAFLMapSwapObserver::new(&mut first_map_observer, &mut second_map_observer);

        // create a combined map observer, e.g. for calibration
        // we use MultiMapObserver::differential to indicate that we want to use the observer in
        // differential mode
        let map_observer = unsafe {
            HitcountsIterableMapObserver::new(MultiMapObserver::differential(
                "combined-edges",
                &mut COMBINED_EDGES,
            ))
        };

        (
            first_map_observer,
            second_map_observer,
            map_swapper,
            map_observer,
        )
    };
    #[cfg(not(feature = "multimap"))]
    let (first_map_observer, second_map_observer, map_swapper, map_observer) = {
        // initialize the map
        unsafe {
            let layout = Layout::from_size_align(MAX_EDGES_NUM * 2, 64).unwrap();
            EDGES = core::slice::from_raw_parts_mut(alloc_zeroed(layout), MAX_EDGES_NUM * 2);
        }

        // create the base maps used to observe the different executors by splitting a slice
        let mut first_map_observer = unsafe {
            StdMapObserver::from_mut_ptr("first-edges", EDGES.as_mut_ptr(), MAX_EDGES_NUM)
        };
        let mut second_map_observer = unsafe {
            StdMapObserver::from_mut_ptr(
                "second-edges",
                EDGES.as_mut_ptr().add(MAX_EDGES_NUM),
                MAX_EDGES_NUM,
            )
        };

        // create a map swapper so that we can replace the coverage map pointer (requires feature pointer_maps!)
        let map_swapper =
            DifferentialAFLMapSwapObserver::new(&mut first_map_observer, &mut second_map_observer);

        // create a combined map observer, e.g. for calibration
        // we use StdMapObserver::differential to indicate that we want to use the observer in
        // differential mode
        let map_observer = unsafe {
            HitcountsMapObserver::new(StdMapObserver::differential_from_mut_ptr(
                "combined-edges",
                EDGES.as_mut_ptr(),
                MAX_EDGES_NUM * 2,
            ))
        };

        (
            first_map_observer,
            second_map_observer,
            map_swapper,
            map_observer,
        )
    };

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
    let mon = SimpleMonitor::new(|s| println!("{s}"));
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
    let first_executor = InProcessExecutor::new(
        &mut first_harness,
        tuple_list!(first_map_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the first executor");
    let second_executor = InProcessExecutor::new(
        &mut second_harness,
        tuple_list!(second_map_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the second executor");

    // create the differential executor, providing both the map swapper (which will ensure the
    // instrumentation picks the correct map to write to) and the map observer (which provides the
    // combined feedback)
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
