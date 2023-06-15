use std::path::{Path, PathBuf};

use libafl::{
    bolts::{
        rands::{RandomSeed, StdRand},
        tuples::tuple_list,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::BytesInput,
    monitors::tui::{ui::TuiUI, TuiMonitor},
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};
use libafl_nyx::{executor::NyxExecutor, helper::NyxHelper};

fn main() {
    let share_dir = Path::new("/tmp/nyx_libxml2/");
    let cpu_id = 0;
    let parallel_mode = false;

    // nyx stuff
    let mut helper = NyxHelper::new(share_dir, cpu_id, true, parallel_mode, None).unwrap();
    let observer =
        unsafe { StdMapObserver::from_mut_ptr("trace", helper.trace_bits, helper.map_size) };

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
    let ui = TuiUI::new(String::from("test_fuzz"), true);
    let monitor = TuiMonitor::new(ui);

    let mut mgr = SimpleEventManager::new(monitor);
    let mut executor = NyxExecutor::new(&mut helper, tuple_list!(observer)).unwrap();
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // start fuzz
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error when fuzz");
}
