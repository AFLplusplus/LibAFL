use std::boxed::Box;

use afl::corpus::{Corpus, InMemoryCorpus, Testcase};
use afl::engines::{DefaultEngine, DefaultState, Engine};
use afl::executors::inmemory::InMemoryExecutor;
use afl::executors::{Executor, ExitKind};
use afl::inputs::bytes::BytesInput;
use afl::mutators::scheduled::{mutation_bitflip, ComposedByMutations, DefaultScheduledMutator};
use afl::stages::mutational::DefaultMutationalStage;
use afl::utils::DefaultRand;

extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;
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

    let executor = InMemoryExecutor::<BytesInput>::new(harness);
    let mut state = DefaultState::new(corpus, executor);

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
