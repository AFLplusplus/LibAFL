use libafl::prelude::*;

fn main() {
/* Your harness function */

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");


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


let mutator = StdScheduledMutator::new(havoc_mutations());


let mut stages = tuple_list!(StdMutationalStage::new(mutator));








fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

}