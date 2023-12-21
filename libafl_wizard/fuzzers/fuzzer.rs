use libafl::        corpus::{InMemoryCorpus, OnDiskCorpus},executors::        corpus::{InMemoryCorpus, OnDiskCorpus},inprocess::InProcessExecutor;
use libafl_bolts::        current_nanos,tuples::        rands::StdRand,tuple_list;
use std::path::PathBuf;

fn main() {
    let mut objective = CrashFeedback::new();

    let mut feedback = MaxMapFeedback::new(&observer);

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let mon = SimpleMonitor::new(|s| println!("{s}"));

    let mut mgr = SimpleEventManager::new(mon);

    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    let mutator = StdScheduledMutator::new(havoc_mutations());

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

}