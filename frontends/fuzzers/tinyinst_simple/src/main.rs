use std::path::PathBuf;

use libafl::{
    bolts::{
        rands::{RandomSeed, StdRand},
        tuples::tuple_list,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, ListFeedback},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::ListObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};
use libafl_tinyinst::executor::TinyInstExecutor;
static mut COVERAGE: Vec<u64> = vec![];

fn main() {
    // Tinyinst things
    let tinyinst_args = vec!["-instrument_module".to_string(), "test.exe".to_string()];

    let args = vec![".\\test\\test.exe".to_string(), "@@".to_string()];

    let observer = ListObserver::new("cov", unsafe { &mut COVERAGE });
    let mut feedback = ListFeedback::new_with_observer(&observer);

    let input = BytesInput::new(b"bad".to_vec());
    let rand = StdRand::new();
    let mut corpus = CachedOnDiskCorpus::new(PathBuf::from("./corpus_discovered"), 64).unwrap();
    corpus
        .add(Testcase::new(input))
        .expect("error in adding corpus");
    let solutions = OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap();

    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = SimpleMonitor::new(|x| println!("{}", x));

    let mut mgr = SimpleEventManager::new(monitor);
    let mut executor = unsafe {
        TinyInstExecutor::new(
            &mut COVERAGE,
            tinyinst_args,
            args,
            5000,
            tuple_list!(observer),
        )
    };
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in fuzzing loop");
}
