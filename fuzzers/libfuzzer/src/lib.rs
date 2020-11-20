use std::boxed::Box;
use std::cell::RefCell;
use std::rc::Rc;

use afl::corpus::{Corpus, InMemoryCorpus, Testcase};
use afl::engines::{DefaultEngine, DefaultState, Engine, State};
use afl::executors::inmemory::InMemoryExecutor;
use afl::executors::{Executor, ExitKind};
use afl::feedbacks::{create_history_map, MaxMapFeedback};
use afl::inputs::bytes::BytesInput;
use afl::mutators::scheduled::{mutation_bitflip, ComposedByMutations, DefaultScheduledMutator};
use afl::observers::DefaultMapObserver;
use afl::stages::mutational::DefaultMutationalStage;
use afl::utils::DefaultRand;

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
    let rand = DefaultRand::new(0).into();

    let mut corpus = InMemoryCorpus::<BytesInput, _>::new(&rand);
    let testcase = Testcase::new(vec![0; 4]).into();
    corpus.add(testcase);

    let edges_observer = Rc::new(RefCell::new(DefaultMapObserver::new_from_ptr(
        unsafe { __lafl_edges_map },
        unsafe { __lafl_max_edges_size as usize },
    )));
    let edges_history_map = create_history_map::<u8>(MAP_SIZE);
    let edges_feedback = MaxMapFeedback::new(edges_observer.clone(), edges_history_map);

    let executor = InMemoryExecutor::<BytesInput>::new(harness);
    let mut state = DefaultState::new(corpus, executor);
    state.add_observer(edges_observer);
    state.add_feedback(Box::new(edges_feedback));

    let mut engine = DefaultEngine::new();
    let mut mutator = DefaultScheduledMutator::new(&rand);
    mutator.add_mutation(mutation_bitflip);
    let stage = DefaultMutationalStage::new(&rand, mutator);
    engine.add_stage(Box::new(stage));

    //

    for i in 0..1000 {
        engine
            .fuzz_one(&mut state)
            .expect(&format!("Error in iter {}", i));
    }
    println!("OK");
}
