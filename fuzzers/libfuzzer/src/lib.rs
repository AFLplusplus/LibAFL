#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::RefCell;

#[cfg(feature = "std")]
use std::io::stderr;

use afl::corpus::InMemoryCorpus;
use afl::engines::{generate_initial_inputs, Engine, State, StdEngine, StdState};
use afl::events::LoggerEventManager;
use afl::executors::inmemory::InMemoryExecutor;
use afl::executors::{Executor, ExitKind};
use afl::feedbacks::MaxMapFeedback;
use afl::generators::RandPrintablesGenerator;
use afl::mutators::scheduled::HavocBytesMutator;
use afl::observers::StdMapObserver;
use afl::stages::mutational::StdMutationalStage;
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

#[no_mangle]
pub extern "C" fn afl_libfuzzer_main() {
    let mut rand = StdRand::new(0);

    let mut corpus = InMemoryCorpus::new();
    let mut generator = RandPrintablesGenerator::new(32);

    // TODO: No_std event manager
    #[cfg(feature = "std")]
    let mut events = LoggerEventManager::new(stderr());

    let edges_observer = Rc::new(RefCell::new(StdMapObserver::new_from_ptr(
        unsafe { __lafl_edges_map },
        unsafe { __lafl_max_edges_size as usize },
    )));
    let edges_feedback = MaxMapFeedback::new(edges_observer.clone(), MAP_SIZE);

    let executor = InMemoryExecutor::new(harness);
    let mut state = StdState::new(executor);
    state.add_observer(edges_observer);
    state.add_feedback(Box::new(edges_feedback));

    generate_initial_inputs(
        &mut rand,
        &mut state,
        &mut corpus,
        &mut generator,
        &mut events,
        4,
    )
    .expect("Failed to load initial inputs");

    let mut engine = StdEngine::new();
    let mutator = HavocBytesMutator::new_default();
    let stage = StdMutationalStage::new(mutator);
    engine.add_stage(Box::new(stage));

    engine
        .fuzz_loop(&mut rand, &mut state, &mut corpus, &mut events)
        .expect("Fuzzer fatal error");
    #[cfg(feature = "std")]
    println!("OK");
}
