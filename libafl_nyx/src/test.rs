use std::{
    ffi::OsString,
    iter::Intersperse,
    path::{Path, PathBuf},
    str::FromStr,
};

use libafl::{
    bolts::{
        rands::{RandomSeed, Xoshiro256StarRand},
        shmem::StdShMemProvider,
    },
    corpus::{self, Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{Executor, InProcessExecutor},
    feedbacks::{CrashFeedback, MapFeedback, MaxMapFeedback},
    fuzzer,
    inputs::{BytesInput, Input, HasBytesVec},
    monitors::{Monitor, MultiMonitor, NopMonitor, SimpleMonitor},
    observers::{Observer, StdMapObserver},
    schedulers::{RandScheduler, Scheduler},
    state::StdState,
    StdFuzzer,
};

use crate::executor::{NyxHelper, NyxInprocessExecutor};

#[test]
fn test_nyxhelper() {
    let share_dir = PathBuf::from_str("tmp/nyx_libxml2/").unwrap();
    let cpu_id = 0;
    let snap_mode = true;
    let nyx_type = crate::executor::NyxProcessType::ALONE;
    let helper = NyxHelper::new(share_dir, cpu_id, snap_mode, nyx_type);
}

#[test]
fn test_executor() {
    let share_dir = PathBuf::from_str("tmp/nyx_libxml2/").unwrap();
    let cpu_id = 0;
    let snap_mode = true;
    let executor = NyxInprocessExecutor::new(share_dir, cpu_id, snap_mode).unwrap();

    // prepare state
    let input = BytesInput::new(b"ss".to_vec());
    let rand = Xoshiro256StarRand::new();
    let corpus = InMemoryCorpus::<BytesInput>::new();
    let solutions = OnDiskCorpus::<BytesInput>::new(PathBuf::from("./crashes")).unwrap();

    let trace_bits = executor.get_trace_bits();
    let observer = StdMapObserver::new("trace", trace_bits);
    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();
    let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();

    let Scheduler = RandScheduler::new();
    let mut fuzzer = StdFuzzer::new(Scheduler, feedback, objective);

    let monitor = NopMonitor::new();
    let mgr = SimpleEventManager::new(monitor);
    // prepare
    executor.run_target(&mut fuzzer, &mut state, &mut mgr, &input);
}
