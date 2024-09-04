use std::path::PathBuf;

use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::BytesInput,
    monitors::tui::TuiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use libafl_nyx::{executor::NyxExecutor, helper::NyxHelper, settings::NyxSettings};

fn main() {
    // nyx stuff
    let settings = NyxSettings::builder().cpu_id(0).parent_cpu_id(None).build();
    let helper = NyxHelper::new("/tmp/nyx_libxml2/", settings).unwrap();
    let observer =
        unsafe { StdMapObserver::from_mut_ptr("trace", helper.bitmap_buffer, helper.bitmap_size) };

    let input = BytesInput::new(b"22".to_vec());
    let rand = StdRand::new();
    let mut corpus = CachedOnDiskCorpus::new(PathBuf::from("./corpus_discovered"), 64).unwrap();
    corpus
        .add(Testcase::new(input))
        .expect("error in adding corpus");
    let solutions = OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap();

    // libafl stuff
    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // switch monitor if you want
    // let monitor = SimpleMonitor::new(|x|-> () {println!("{}",x)});
    let monitor = TuiMonitor::builder().title("test_fuzz").build();

    let mut mgr = SimpleEventManager::new(monitor);
    let mut executor = NyxExecutor::builder().build(helper, tuple_list!(observer));
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // start fuzz
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error when fuzz");
}
