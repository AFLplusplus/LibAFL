use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    str::FromStr,
};

use libafl::{
    bolts::{
        rands::{RandomSeed, Xoshiro256StarRand},
        shmem::StdShMemProvider, tuples::tuple_list,
    },
    corpus::{self, Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::{SimpleEventManager, NopEventManager},
    executors::{Executor, InProcessExecutor},
    feedbacks::{CrashFeedback, MapFeedback, MaxMapFeedback},
    fuzzer,
    inputs::{BytesInput, Input, HasBytesVec},
    monitors::{Monitor, MultiMonitor, NopMonitor, SimpleMonitor, tui::TuiMonitor},
    observers::{Observer, StdMapObserver},
    schedulers::{RandScheduler, Scheduler},
    state::StdState,
    StdFuzzer, ExecutesInput, Fuzzer, mutators::{StdScheduledMutator, ByteDecMutator, havoc_mutations}, stages::StdMutationalStage,
};

use crate::executor::{NyxHelper, NyxInprocessExecutor};

#[test]
fn test_nyxhelper() {
    let share_dir = PathBuf::from_str("/tmp/nyx_libxml2/").unwrap();
    let cpu_id = 0;
    let snap_mode = true;
    let nyx_type = crate::executor::NyxProcessType::ALONE;
    let helper = NyxHelper::new(share_dir, cpu_id, snap_mode, nyx_type);
}

#[test]
fn test_executor() {
    let share_dir = PathBuf::from_str("/tmp/nyx_libxml2/").unwrap();
    let cpu_id = 0;
    let snap_mode = true;

    // prepare state
    let mut input = BytesInput::new(b"ss".to_vec());
    let rand
     = Xoshiro256StarRand::new();
    let mut corpus = InMemoryCorpus::<BytesInput>::new();
    corpus.add(Testcase::new(input));
    let solutions = OnDiskCorpus::<BytesInput>::new(PathBuf::from("./crashes")).unwrap();

    let mut helper = NyxHelper::new(share_dir,cpu_id,true,crate::executor::NyxProcessType::ALONE).unwrap();
    let mut trace_bits = unsafe {std::slice::from_raw_parts_mut(helper.trace_bits, helper.map_size)};
    let mut observer = StdMapObserver::new("trace", trace_bits);
    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    // let monitor = SimpleMonitor::new(|x|-> () {println!("{}",x)});
    let monitor = TuiMonitor::new("test_fuzz",true);
    let mut mgr:SimpleEventManager<BytesInput, _, _> = SimpleEventManager::new(monitor);
    // prepare
    let mut executor = NyxInprocessExecutor::new(&mut helper,tuple_list!(observer)).unwrap();
    // fuzzer.execute_input(&mut state,&mut executor,&mut mgr,&mut input);

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    
    fuzzer.fuzz_loop(&mut stages,&mut executor,&mut state,&mut mgr).expect("error when fuzz");
}


