use std::path::PathBuf;

use libafl::{
    bolts::{
        rands::{RandomSeed, StdRand},
        tuples::tuple_list,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};

use libafl_tinyinst::executor::TinyInstExecutor;

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 8 * 1024 * 1024] = [0; 8 * 1024 * 1024];

fn main() {
    // Tinyinst things
    let tinyinst_args = vec![
        "-instrument_module".to_string(),
        "test.exe".to_string(),
        "-coverage_file".to_string(),
        "coverage.txt".to_string(),
    ];

    // let args = vec![".\\test\\test.exe".to_string(), "cur_file".to_string()];
    let args = vec![".\\test\\test.exe".to_string(), "cur_file".to_string()];
    let observer =
        unsafe { StdMapObserver::new_from_ptr("signals", SIGNALS.as_mut_ptr(), SIGNALS.len()) };

    let input = BytesInput::new(b"bad12".to_vec());
    let rand = StdRand::new();
    let mut corpus = CachedOnDiskCorpus::new(PathBuf::from("./corpus_discovered"), 64).unwrap();
    corpus
        .add(Testcase::new(input))
        .expect("error in adding corpus");
    let solutions = OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap();

    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let monitor = SimpleMonitor::new(|s| println!("{}", s));

    let mut mgr: SimpleEventManager<BytesInput, _, _> = SimpleEventManager::new(monitor);
    let mut executor = unsafe {
        TinyInstExecutor::new(
            tinyinst_args,
            args,
            5000,
            tuple_list!(observer),
            SIGNALS.as_mut_ptr(),
            SIGNALS.len(),
        )
    };
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in fuzzing loop");
}
