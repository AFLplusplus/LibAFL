#![no_std]
// Embedded targets: build with no_main
#![cfg_attr(not(any(windows)), no_main)]

#[cfg(any(windows, unix))]
extern crate alloc;
#[cfg(any(windows, unix))]
use alloc::ffi::CString;
#[cfg(not(any(windows)))]
use core::panic::PanicInfo;

use libafl::{
    corpus::InMemoryCorpus,
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::ConstMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{nonnull_raw_mut, nonzero, rands::StdRand, tuples::tuple_list, AsSlice};
#[cfg(any(windows, unix))]
use libc::{abort, printf};
use static_alloc::Bump;

#[global_allocator]
static A: Bump<[u8; 512 * 1024 * 1024]> = Bump::uninit();

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    #[cfg(unix)]
    unsafe {
        abort();
    }
    #[cfg(not(unix))]
    loop {
        // On embedded, there's not much left to do.
    }
}

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}

/// Provide custom time in `no_std` environment
/// Use a time provider of your choice
#[no_mangle]
pub extern "C" fn external_current_millis() -> u64 {
    // TODO: use "real" time here
    1000
}

/// The main of this program.
/// # Panics
/// Will panic once the fuzzer finds the correct conditions.
#[no_mangle]
pub extern "C" fn main(_argc: isize, _argv: *const *const u8) -> isize {
    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0);
        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1);
            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2);
                #[expect(clippy::manual_assert)]
                if buf.len() > 2 && buf[2] == b'c' {
                    panic!("=)");
                }
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    let observer = unsafe { ConstMapObserver::from_mut_ptr("signals", nonnull_raw_mut!(SIGNALS)) };
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
        InMemoryCorpus::new(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| {
        // TODO: Print `s` here, if your target permits it.
        #[cfg(any(windows, unix))]
        unsafe {
            let s = CString::new(s).unwrap();
            printf(c"%s\n".as_ptr().cast(), s.as_ptr());
        }
    });

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));

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

    0
}
