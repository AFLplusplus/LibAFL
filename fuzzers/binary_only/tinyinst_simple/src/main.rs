use std::{path::PathBuf, time::Duration};

use libafl::{
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
#[cfg(unix)]
use libafl_bolts::shmem::UnixShMemProvider;
#[cfg(windows)]
use libafl_bolts::shmem::Win32ShMemProvider;
use libafl_bolts::{
    ownedref::OwnedMutPtr, rands::StdRand, shmem::ShMemProvider, tuples::tuple_list,
};
use libafl_tinyinst::executor::TinyInstExecutor;
static mut COVERAGE: Vec<u64> = vec![];

#[cfg(not(any(target_vendor = "apple", windows, target_os = "linux")))]
fn main() {}

#[cfg(any(target_vendor = "apple", windows, target_os = "linux"))]
fn main() {
    // Tinyinst things
    let tinyinst_args = vec!["-instrument_module".to_string(), "test.exe".to_string()];

    // use shmem to pass testcases
    let args = vec!["test.exe".to_string(), "-m".to_string(), "@@".to_string()];

    // use file to pass testcases
    // let args = vec!["test.exe".to_string(), "-f".to_string(), "@@".to_string()];

    let coverage = OwnedMutPtr::Ptr(&raw mut COVERAGE);
    let observer = ListObserver::new("cov", coverage);
    let mut feedback = ListFeedback::new(&observer);
    #[cfg(windows)]
    let mut shmem_provider = Win32ShMemProvider::new().unwrap();

    #[cfg(unix)]
    let mut shmem_provider = UnixShMemProvider::new().unwrap();

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

    let monitor = SimpleMonitor::new(|x| println!("{x}"));

    let mut mgr = SimpleEventManager::new(monitor);
    let mut executor = TinyInstExecutor::builder()
        .tinyinst_args(tinyinst_args)
        .program_args(args)
        .use_shmem()
        .persistent("test.exe".to_string(), "fuzz".to_string(), 1, 10000)
        .timeout(Duration::new(5, 0))
        .shmem_provider(&mut shmem_provider)
        .coverage_ptr(&raw mut COVERAGE)
        .build(tuple_list!(observer))
        .unwrap();

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in fuzzing loop");
}
