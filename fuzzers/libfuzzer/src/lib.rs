#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::RefCell;

use afl::corpus::{Corpus, InMemoryCorpus, Testcase};
use afl::engines::{Engine, State, StdEngine, StdState};
use afl::events::LoggerEventManager;
use afl::executors::inmemory::InMemoryExecutor;
use afl::executors::{Executor, ExitKind};
use afl::feedbacks::{create_history_map, MaxMapFeedback};
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

    let mut corpus = InMemoryCorpus::new();
    let testcase = Testcase::new(vec![0; 4]).into();
    corpus.add(testcase);

    let edges_observer = Rc::new(RefCell::new(StdMapObserver::new_from_ptr(
        unsafe { __lafl_edges_map },
        unsafe { __lafl_max_edges_size as usize },
    )));
    let edges_history_map = create_history_map::<u8>(MAP_SIZE);
    let edges_feedback = MaxMapFeedback::new(edges_observer.clone(), edges_history_map);

    let executor = InMemoryExecutor::<BytesInput>::new(harness);
    let mut state = StdState::new(corpus, executor);
    state.add_observer(edges_observer);
    state.add_feedback(Box::new(edges_feedback));

    let mut engine = StdEngine::new();
    let mutator = HavocBytesMutator::new_default();
    let stage = StdMutationalStage::new(mutator);
    engine.add_stage(Box::new(stage));

    let mut events = LoggerEventManager::new();

    for i in 0..1000 {
        engine
            .fuzz_one(&mut rand, &mut state, &mut events)
            .expect(&format!("Error in iter {}", i));
    }
    #[cfg(feature = "std")]
    println!("OK");
}
