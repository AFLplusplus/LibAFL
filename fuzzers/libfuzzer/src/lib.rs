#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::boxed::Box;

#[cfg(feature = "std")]
use std::io::stderr;

use afl::corpus::InMemoryCorpus;
use afl::engines::Engine;
use afl::engines::Fuzzer;
use afl::engines::State;
use afl::engines::StdFuzzer;
use afl::events::LoggerEventManager;
use afl::executors::inmemory::InMemoryExecutor;
use afl::executors::{Executor, ExitKind};
use afl::feedbacks::MaxMapFeedback;
use afl::generators::RandPrintablesGenerator;
use afl::mutators::scheduled::HavocBytesMutator;
use afl::mutators::HasMaxSize;
use afl::observers::StdMapObserver;
use afl::stages::mutational::StdMutationalStage;
use afl::tuples::tuple_list;
use afl::utils::StdRand;

const MAP_SIZE: usize = 65536;

#[no_mangle]
extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    static __lafl_edges_map: *mut u8;
    static __lafl_cmp_map: *mut u8;
    static __lafl_max_edges_size: u32;
}

fn harness<I>(_executor: &dyn Executor<I>, buf: &[u8]) -> ExitKind {
    unsafe {
        LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len());
    }
    ExitKind::Ok
}

const NAME_COV_MAP: &str = "cov_map";

#[no_mangle]
pub extern "C" fn afl_libfuzzer_main() {
    let mut rand = StdRand::new(0);

    let mut corpus = InMemoryCorpus::new();
    let mut generator = RandPrintablesGenerator::new(32);

    // TODO: No_std event manager
    #[cfg(feature = "std")]
    let mut events = LoggerEventManager::new(stderr());

    let edges_observer =
        StdMapObserver::new_from_ptr(&NAME_COV_MAP, unsafe { __lafl_edges_map }, unsafe {
            __lafl_max_edges_size as usize
        });
    let edges_feedback = MaxMapFeedback::new_with_observer(&NAME_COV_MAP, &edges_observer);

    let executor = InMemoryExecutor::new("Libfuzzer", harness, tuple_list!(edges_observer));
    let mut state = State::new(tuple_list!(edges_feedback));

    let mut engine = Engine::new(executor);

    state
        .generate_initial_inputs(
            &mut rand,
            &mut corpus,
            &mut generator,
            &mut engine,
            &mut events,
            4,
        )
        .expect("Failed to load initial inputs");

    let mut mutator = HavocBytesMutator::new_default();
    mutator.set_max_size(4096);

    let stage = StdMutationalStage::new(mutator);
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    fuzzer
        .fuzz_loop(&mut rand, &mut state, &mut corpus, &mut engine, &mut events)
        .expect("Fuzzer fatal error");
    #[cfg(feature = "std")]
    println!("OK");
}
