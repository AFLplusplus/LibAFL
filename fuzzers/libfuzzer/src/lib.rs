#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::RefCell;

use afl::corpus::{Corpus, InMemoryCorpus, Testcase};
use afl::engines::{generate_initial_inputs, Engine, State, StdEngine, StdState};
use afl::events::LoggerEventManager;
use afl::executors::inmemory::InMemoryExecutor;
use afl::executors::{Executor, ExitKind};
use afl::feedbacks::{create_history_map, MaxMapFeedback};
use afl::generators::{Generator, RandPrintablesGenerator};
use afl::inputs::bytes::BytesInput;
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

    let corpus = InMemoryCorpus::new();
    let mut generator = RandPrintablesGenerator::new(4096);
    let mut events = LoggerEventManager::new();

    let edges_observer = Rc::new(RefCell::new(StdMapObserver::new_from_ptr(
        unsafe { __lafl_edges_map },
        unsafe { __lafl_max_edges_size as usize },
    )));
    let edges_history_map = create_history_map::<u8>(MAP_SIZE);
    let edges_feedback = MaxMapFeedback::new(edges_observer.clone(), edges_history_map);

    let executor = InMemoryExecutor::new(harness);
    let mut state = StdState::new(corpus, executor);
    state.add_observer(edges_observer);
    state.add_feedback(Box::new(edges_feedback));

    generate_initial_inputs(&mut rand, &mut state, &mut generator, &mut events, 4)
        .expect("Failed to load initial inputs");

    let mut engine = StdEngine::new();
    let mutator = HavocBytesMutator::new_default();
    let stage = StdMutationalStage::new(mutator);
    engine.add_stage(Box::new(stage));

    engine
        .fuzz_loop(&mut rand, &mut state, &mut events)
        .expect("Fuzzer fatal error");
    #[cfg(feature = "std")]
    println!("OK");
}
