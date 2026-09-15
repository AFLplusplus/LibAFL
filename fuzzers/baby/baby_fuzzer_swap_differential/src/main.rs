use std::{
    alloc::{alloc_zeroed, Layout},
    path::PathBuf,
};

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    corpus::{InMemoryCorpus, InMemoryOnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, DiffExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{nonzero, rands::StdRand, tuples::tuple_list};
use libafl_targets::{edges_max_num, DifferentialAFLMapSwapObserver};
#[cfg(not(miri))]
use mimalloc::MiMalloc;

#[global_allocator]
#[cfg(not(miri))]
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
    pub use libafl_bolts::ownedref::OwnedMutSlice;
}
#[cfg(feature = "multimap")]
use multimap::{HitcountsIterableMapObserver, MultiMapObserver, OwnedMutSlice};

#[cfg(not(feature = "multimap"))]
mod slicemap {
    pub use libafl::observers::HitcountsMapObserver;

    pub static mut EDGES: &mut [u8] = &mut [];
}
#[cfg(not(feature = "multimap"))]
use slicemap::{HitcountsMapObserver, EDGES};

#[expect(clippy::too_many_lines)]
pub fn main() {
    // The closure that we want to fuzz
    let mut first_harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = &target;
        if unsafe { inspect_first(buf.as_ptr(), buf.len()) } {
            ExitKind::Crash
        } else {
            ExitKind::Ok
        }
    };
    let mut second_harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = &target;
        if unsafe { inspect_second(buf.as_ptr(), buf.len()) } {
            ExitKind::Crash
        } else {
            ExitKind::Ok
        }
    };

    let num_edges: usize = edges_max_num(); // upper bound

    #[cfg(feature = "multimap")]
    let (
        first_map_observer,
        second_map_observer,
        map_swapper,
        map_observer,
        layout,
        first_edges,
        second_edges,
    ) = {
        // initialize the maps
        let layout = Layout::from_size_align(num_edges, 64).unwrap();
        let first_edges = unsafe { (alloc_zeroed(layout), num_edges) };
        let second_edges = unsafe { (alloc_zeroed(layout), num_edges) };

        let combined_edges = unsafe {
            vec![
                OwnedMutSlice::from_raw_parts_mut(first_edges.0, first_edges.1),
                OwnedMutSlice::from_raw_parts_mut(second_edges.0, second_edges.1),
            ]
        };

        // create the base maps used to observe the different executors from two independent maps
        // TODO: Replace with ConstMapObserver
        let mut first_map_observer =
            unsafe { StdMapObserver::from_mut_ptr("first-edges", first_edges.0, first_edges.1) };
        let mut second_map_observer =
            unsafe { StdMapObserver::from_mut_ptr("second-edges", second_edges.0, second_edges.1) };

        // create a map swapper so that we can replace the coverage map pointer (requires feature pointer_maps!)
        let map_swapper =
            DifferentialAFLMapSwapObserver::new(&mut first_map_observer, &mut second_map_observer);

        // create a combined map observer, e.g. for calibration
        // we use MultiMapObserver::differential to indicate that we want to use the observer in
        // differential mode
        let map_observer = HitcountsIterableMapObserver::new(MultiMapObserver::differential(
            "combined-edges",
            combined_edges,
        ));

        (
            first_map_observer,
            second_map_observer,
            map_swapper,
            map_observer,
            layout,
            first_edges,
            second_edges,
        )
    };
    #[cfg(not(feature = "multimap"))]
    let (first_map_observer, second_map_observer, map_swapper, map_observer) = {
        // initialize the map
        unsafe {
            let layout = Layout::from_size_align(num_edges * 2, 64).unwrap();
            EDGES = core::slice::from_raw_parts_mut(alloc_zeroed(layout), num_edges * 2);
        }

        let edges_ptr: *mut u8 = &raw mut EDGES as _;

        // create the base maps used to observe the different executors by splitting a slice
        // TODO: Replace with ConstMapObserver
        let mut first_map_observer =
            unsafe { StdMapObserver::from_mut_ptr("first-edges", edges_ptr, num_edges) };
        let mut second_map_observer = unsafe {
            StdMapObserver::from_mut_ptr("second-edges", edges_ptr.add(num_edges), num_edges)
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
                edges_ptr,
                num_edges * 2,
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
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        InMemoryOnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
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
    let mon = TuiMonitor::builder()
        .title("Baby Fuzzer")
        .enhanced_graphics(false)
        .build();

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // Setup a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let stages = tuple_list!(StdMutationalStage::new(mutator));

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective, stages);

    // Create the executor for an in-process function with just one observer
    let first_executor = InProcessExecutor::builder()
        .harness(&mut first_harness)
        .observers(tuple_list!(first_map_observer))
        .fuzzer(&mut fuzzer)
        .state(&mut state)
        .event_mgr(&mut mgr)
        .build()
        .expect("Failed to create the first executor");
    let second_executor = InProcessExecutor::builder()
        .harness(&mut second_harness)
        .observers(tuple_list!(second_map_observer))
        .fuzzer(&mut fuzzer)
        .state(&mut state)
        .event_mgr(&mut mgr)
        .build()
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
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

    // Generate 8 initial inputs
    fuzzer
        .generate_initial_inputs_with_executor(
            &mut differential_executor,
            &mut generator,
            &mut state,
            &mut mgr,
            8,
        )
        .expect("Failed to generate the initial corpus");

    fuzzer
        .fuzz_loop(&mut differential_executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    #[cfg(feature = "multimap")]
    unsafe {
        std::alloc::dealloc(first_edges.0, layout);
        std::alloc::dealloc(second_edges.0, layout);
    }
}
