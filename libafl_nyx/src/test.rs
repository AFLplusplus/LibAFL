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
/// then you need to follow <https://github.com/AFLplusplus/AFLplusplus/tree/stable/nyx_mode> to set up libxml2 in /`tmp/nyx_libxml2`/
#[allow(unused_imports)]
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

#[cfg(not(test))]
#[test]
fn test_nyxhelper() {
    let share_dir = Path::new("/tmp/nyx_libxml2/");
    let cpu_id = 0;
    let snap_mode = true;
    let parallel_mode = false;
    let helper = NyxHelper::new(share_dir, cpu_id, snap_mode, parallel_mode, None)
        .expect("error when create Nyxhelper");
    helper.set_timeout(Duration::new(10, 0));
}
