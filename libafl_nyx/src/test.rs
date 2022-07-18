#[allow(unused_imports)]
use crate::executor::NyxExecutor;
#[allow(unused_imports)]
use crate::helper::{NyxHelper, NyxProcessType};
#[allow(unused_imports)]
use libafl::{
    bolts::{
        rands::{RandomSeed, Xoshiro256StarRand},
        shmem::StdShMemProvider,
        tuples::tuple_list,
    },
    corpus::{self, Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::{NopEventManager, SimpleEventManager},
    executors::{Executor, InProcessExecutor},
    feedbacks::{CrashFeedback, MapFeedback, MaxMapFeedback},
    fuzzer,
    inputs::{BytesInput, HasBytesVec, Input},
    monitors::{tui::TuiMonitor, Monitor, MultiMonitor, NopMonitor, SimpleMonitor},
    mutators::{havoc_mutations, ByteDecMutator, StdScheduledMutator},
    observers::{Observer, StdMapObserver},
    schedulers::{RandScheduler, Scheduler},
    stages::StdMutationalStage,
    state::StdState,
    ExecutesInput, Fuzzer, StdFuzzer,
};
/// contains function for local test and shouldn't run in CI.
/// To enable in local, please unset `test` feature in your IDE(e.g. 'Rust-analyzer>Cargo: Unset Test' in VSCODE)
/// then you need to follow https://github.com/AFLplusplus/AFLplusplus/tree/stable/nyx_mode to set up libxml2 in /tmp/nyx_libxml2/
#[allow(unused_imports)]
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    str::FromStr,
};

#[cfg(not(test))]
#[test]
fn test_nyxhelper() {
    let share_dir = Path::new("/tmp/nyx_libxml2/");
    let cpu_id = 0;
    let snap_mode = true;
    let nyx_type = crate::executor::NyxProcessType::ALONE;
    let helper = NyxHelper::new(share_dir, cpu_id, snap_mode, nyx_type)
        .expect("error when create Nyxhelper");
    helper.set_timeout(10, 0);
}

#[cfg(not(test))]
#[test]
fn test_standalone_executor() {
    let share_dir = Path::new("/tmp/nyx_libxml2/");
    let cpu_id = 0;
    let parallel_mode = false;

    // nyx stuff
    let mut helper = NyxHelper::new(share_dir, cpu_id, true, parallel_mode, None).unwrap();
    let trace_bits = unsafe { std::slice::from_raw_parts_mut(helper.trace_bits, helper.map_size) };
    let observer = StdMapObserver::new("trace", trace_bits);

    let input = BytesInput::new(b"22".to_vec());
    let rand = Xoshiro256StarRand::new();
    let mut corpus = InMemoryCorpus::<BytesInput>::new();
    corpus
        .add(Testcase::new(input))
        .expect("error in adding corpus");
    let solutions = OnDiskCorpus::<BytesInput>::new(PathBuf::from("./crashes")).unwrap();

    // libafl stuff
    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // switch monitor if you want
    // let monitor = SimpleMonitor::new(|x|-> () {println!("{}",x)});
    let monitor = TuiMonitor::new("test_fuzz".to_string(), true);

    let mut mgr: SimpleEventManager<BytesInput, _, _> = SimpleEventManager::new(monitor);
    let mut executor = NyxExecutor::new(&mut helper, tuple_list!(observer)).unwrap();
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // start fuzz
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error when fuzz");
}
