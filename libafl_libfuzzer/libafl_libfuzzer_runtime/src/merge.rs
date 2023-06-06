use std::{
    env::temp_dir,
    ffi::c_int,
    fmt::Debug,
    fs,
    fs::File,
    io::Write,
    os::fd::{AsRawFd, FromRawFd},
    time::{SystemTime, UNIX_EPOCH},
};

use libafl::{
    bolts::{
        rands::{Rand, RandomSeed, StdRand},
        shmem::{ShMem, ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Named},
        AsIter, AsMutSlice, AsSlice,
    },
    corpus::{Corpus, CorpusMinimizer, InMemoryCorpus, OnDiskCorpus, StdCorpusMinimizer},
    events::{EventRestarter, SimpleEventManager, SimpleRestartingEventManager},
    executors::{
        inprocess::TimeoutInProcessForkExecutor, ExitKind, InProcessExecutor, TimeoutExecutor,
    },
    feedbacks::{MapFeedbackMetadata, MaxMapFeedback},
    inputs::{BytesInput, HasTargetBytes, UsesInput},
    monitors::MultiMonitor,
    observers::{
        HitcountsIterableMapObserver, MapObserver, MultiMapObserver, Observer, StdMapObserver,
        TimeObserver,
    },
    schedulers::QueueScheduler,
    state::{HasCorpus, HasNamedMetadata, HasRand, StdState},
    Error, StdFuzzer,
};
use libafl_targets::COUNTERS_MAPS;
use log::info;
use serde::{Deserialize, Serialize};

use crate::options::LibfuzzerOptions;

pub fn merge(
    options: LibfuzzerOptions,
    harness: &extern "C" fn(*const u8, usize) -> c_int,
) -> Result<(), Error> {
    if options.dirs().len() == 0 {
        return Err(Error::illegal_argument("Missing corpora to minimize; you should provide one directory to minimize into and one-to-many from which the inputs are loaded."));
    }

    let mut rand = StdRand::new();

    let corpus_dir = if options.dirs().first().unwrap().exists()
        && options
            .dirs()
            .first()
            .unwrap()
            .read_dir()?
            .any(|entry| entry.map_or(true, |e| !(e.file_name() == "." || e.file_name() == "..")))
    {
        let temp = temp_dir().join(format!("libafl-merge-{}{}", rand.next(), rand.next()));
        eprintln!("Warning: creating an intermediary directory for minimisation at {}. We will move your existing corpus dir to.", temp.to_str().unwrap());
        temp
    } else {
        options.dirs().first().cloned().unwrap()
    };

    #[cfg(unix)]
    let mut stderr = unsafe {
        let new_fd = libc::dup(std::io::stderr().as_raw_fd().into());
        File::from_raw_fd(new_fd.into())
    };
    let monitor = MultiMonitor::with_time(
        move |s| {
            #[cfg(unix)]
            writeln!(stderr, "{s}").expect("Could not write to stderr???");
            #[cfg(not(unix))]
            eprintln!("{s}");
        },
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
    );

    let mut shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let (state, mut mgr): (
        Option<StdState<_, _, _, _>>,
        SimpleRestartingEventManager<_, StdState<_, _, _, _>, _>,
    ) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider) {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };
    #[cfg(unix)]
    {
        if options.close_fd_mask() != 0 {
            let file_null = File::open("/dev/null")?;
            unsafe {
                if options.close_fd_mask() & 1 != 0 {
                    libc::dup2(file_null.as_raw_fd().into(), 1);
                }
                if options.close_fd_mask() & 2 != 0 {
                    libc::dup2(file_null.as_raw_fd().into(), 2);
                }
            }
        }
    }

    let counters = unsafe { core::mem::take(&mut COUNTERS_MAPS) };
    let edges = HitcountsIterableMapObserver::new(MultiMapObserver::new("edges", counters));

    let time = TimeObserver::new("time");

    let cmin = StdCorpusMinimizer::new(&edges);

    let mut map_feedback = MaxMapFeedback::new(&edges);
    let map_feedback_name = map_feedback.name().to_string();

    let observers = tuple_list!(edges, time);

    let mut state = StdState::new(
        rand,
        OnDiskCorpus::new(corpus_dir.clone()).unwrap(),
        InMemoryCorpus::new(),
        &mut map_feedback,
        &mut (), // no objectives
    )?;

    // scheduler doesn't really matter here
    let scheduler = QueueScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, map_feedback, ());

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();

        harness(buf.as_ptr(), buf.len());

        ExitKind::Ok
    };

    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(&mut harness, observers, &mut fuzzer, &mut state, &mut mgr)?,
        options.timeout(),
    );

    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, options.dirs())?;

    let edge_meta = state
        .named_metadata::<MapFeedbackMetadata<u8>>(&map_feedback_name)
        .unwrap();
    let edges_max = edge_meta.history_map.len();
    let edges = edges_max - bytecount::count(&edge_meta.history_map, 0);

    info!(
        "Loaded {} initial inputs with {}/{} edges; minimizing...",
        state.corpus().count(),
        edges,
        edges_max
    );

    cmin.minimize(&mut fuzzer, &mut executor, &mut mgr, &mut state)?;

    info!(
        "Minimization complete; reduced to {} inputs!",
        state.corpus().count()
    );

    if corpus_dir != options.dirs()[0] {
        let temp = temp_dir().join(format!(
            "libafl-merge-orig-{}{}",
            state.rand_mut().next(),
            state.rand_mut().next()
        ));
        eprintln!(
            "Moving original corpus directory {} to {} and replacing it with minimisation result ({}).",
            options.dirs()[0].to_str().unwrap(),
            temp.to_str().unwrap(),
            corpus_dir.to_str().unwrap()
        );
        fs::rename(&options.dirs()[0], temp)?;
        fs::rename(corpus_dir, &options.dirs()[0])?;
    }

    mgr.send_exiting()
}
