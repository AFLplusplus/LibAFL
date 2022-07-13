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
    corpus::{self, Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{SimpleEventManager, NopEventManager},
    executors::{Executor, InProcessExecutor},
    feedbacks::{CrashFeedback, MapFeedback, MaxMapFeedback},
    fuzzer,
    inputs::{BytesInput, Input, HasBytesVec},
    monitors::{Monitor, MultiMonitor, NopMonitor, SimpleMonitor},
    observers::{Observer, StdMapObserver},
    schedulers::{RandScheduler, Scheduler},
    state::StdState,
    StdFuzzer, ExecutesInput,
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
    let rand = Xoshiro256StarRand::new();
    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = OnDiskCorpus::<BytesInput>::new(PathBuf::from("./crashes")).unwrap();

    let mut helper = NyxHelper::new(share_dir,cpu_id,true,crate::executor::NyxProcessType::ALONE).unwrap();
    let mut trace_bits = unsafe {std::slice::from_raw_parts_mut(helper.trace_bits, helper.map_size)};
    let mut observer = StdMapObserver::new("trace", trace_bits);
    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

    let scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let monitor = SimpleMonitor::new(|x|-> () {println!("{}",x)});
    let mut mgr:SimpleEventManager<BytesInput, _, BytesInput> = SimpleEventManager::new(monitor);
    // prepare
    let mut executor = NyxInprocessExecutor::new(&mut helper,tuple_list!(observer)).unwrap();
    fuzzer.execute_input(&mut state,&mut executor,&mut mgr,&mut input);
}
