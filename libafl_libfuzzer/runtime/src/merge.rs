use std::{
    env::temp_dir,
    ffi::c_int,
    fs::{File, rename},
    io::Write,
    os::fd::{AsRawFd, FromRawFd},
};

use libafl::{
    Error, HasScheduler, StdFuzzer,
    corpus::Corpus,
    events::{SendExiting, SimpleRestartingEventManager},
    executors::{ExitKind, InProcessExecutor},
    feedback_and_fast, feedback_or_fast,
    feedbacks::{CrashFeedback, MinMapFeedback, TimeoutFeedback},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    observers::{MultiMapObserver, TimeObserver},
    schedulers::RemovableScheduler,
    state::{HasCorpus, HasRand, StdState},
};
use libafl_bolts::{
    AsSlice,
    rands::{Rand, StdRand},
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};
use libafl_targets::{OomFeedback, OomObserver, counters_maps_ptr_mut};

use crate::{
    corpus::{ArtifactCorpus, LibfuzzerCorpus},
    feedbacks::{LibfuzzerCrashCauseFeedback, LibfuzzerKeepFeedback},
    observers::{MappedEdgeMapObserver, SizeTimeValueObserver},
    options::LibfuzzerOptions,
    schedulers::MergeScheduler,
};

#[expect(clippy::too_many_lines)]
pub fn merge(
    options: &LibfuzzerOptions,
    harness: &extern "C" fn(*const u8, usize) -> c_int,
) -> Result<(), Error> {
    if options.dirs().is_empty() {
        return Err(Error::illegal_argument(
            "Missing corpora to minimize; you should provide one directory to minimize into and one-to-many from which the inputs are loaded.",
        ));
    }

    let crash_corpus = ArtifactCorpus::new();

    let keep_observer = LibfuzzerKeepFeedback::new();
    let keep = keep_observer.keep();

    let mut shmem_provider = StdShMemProvider::new().unwrap();

    #[cfg(unix)]
    let mut stderr = unsafe {
        let new_fd = libc::dup(std::io::stderr().as_raw_fd());
        File::from_raw_fd(new_fd)
    };
    let monitor = MultiMonitor::new(move |s| {
        #[cfg(unix)]
        writeln!(stderr, "{s}").expect("Could not write to stderr???");
        #[cfg(not(unix))]
        eprintln!("{s}");
    });

    let (state, mut mgr): (
        Option<StdState<_, _, _, _>>,
        SimpleRestartingEventManager<_, _, StdState<_, _, _, _>, _, _>,
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
                    libc::dup2(file_null.as_raw_fd(), 1);
                }
                if options.close_fd_mask() & 2 != 0 {
                    libc::dup2(file_null.as_raw_fd(), 2);
                }
            }
        }
    }

    let edges = unsafe { core::mem::take(&mut *(counters_maps_ptr_mut())) };
    let edges_observer = MultiMapObserver::new("edges", edges);

    let time = TimeObserver::new("time");
    let edges_observer =
        MappedEdgeMapObserver::new(edges_observer, SizeTimeValueObserver::new(time));

    let map_feedback = MinMapFeedback::new(&edges_observer);

    // Create an OOM observer to monitor if an OOM has occurred
    let oom_observer = OomObserver::new(options.rss_limit(), options.malloc_limit());

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_and_fast!(keep_observer, map_feedback);

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(
        LibfuzzerCrashCauseFeedback::new(options.artifact_prefix().clone()),
        OomFeedback,
        CrashFeedback::new(),
        TimeoutFeedback::new()
    );

    let observers = tuple_list!(edges_observer, oom_observer);

    // scheduler doesn't really matter here
    let scheduler = MergeScheduler::new();

    let mut state = state.map_or_else(|| {
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

        StdState::new(
            // RNG
            StdRand::new(),
            // Corpus that will be evolved, we keep it in memory for performance
            LibfuzzerCorpus::new(corpus_dir, 4096),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            crash_corpus,
            // A reference to the feedbacks, to create their feedback state
            &mut feedback,
            // A reference to the objectives, to create their objective state
            &mut objective,
        )
    }, Ok)?;

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective); // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();

        let result = unsafe {
            crate::libafl_libfuzzer_test_one_input(Some(*harness), buf.as_ptr(), buf.len())
        };
        if result == -2 {
            ExitKind::Crash
        } else {
            *keep.borrow_mut() = result == 0;
            ExitKind::Ok
        }
    };

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        observers,
        &mut fuzzer,
        &mut state,
        &mut mgr,
        options.timeout(),
    )?;

    // In case the corpus is empty (on first run) or crashed while loading, reset
    if state.must_load_initial_inputs() && !options.dirs().is_empty() {
        let loaded_dirs = options
            .dirs()
            .iter()
            .filter(|&dir| state.corpus().dir_path() != dir)
            .cloned()
            .collect::<Vec<_>>();
        // Load from disk
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &loaded_dirs)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to load initial corpus at {:?}: {}",
                    options.dirs(),
                    e
                )
            });
    }

    for id in fuzzer.scheduler().removable() {
        let testcase = state.corpus_mut().remove(id)?;
        fuzzer
            .scheduler_mut()
            .on_remove(&mut state, id, &Some(testcase))?;
    }

    for id in fuzzer.scheduler().current().clone() {
        let mut testcase = state.corpus_mut().get(id)?.borrow_mut();
        let file_path = testcase
            .file_path_mut()
            .as_mut()
            .expect("No file backing for corpus entry");
        if let Some((base, _)) = file_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .rsplit_once('-')
        {
            let mut new_file_path = file_path.clone();
            new_file_path.pop();
            new_file_path.push(base);
            if new_file_path.exists() {
                drop(testcase);
                let testcase = state.corpus_mut().remove(id)?;
                fuzzer
                    .scheduler_mut()
                    .on_remove(&mut state, id, &Some(testcase))?;
            } else {
                // False-positive: file_path is used just below
                rename(&file_path, &new_file_path)?;
                *file_path = new_file_path;
            }
        }
    }

    println!(
        "Minimization complete; reduced to {} inputs!",
        state.corpus().count()
    );

    let corpus_dir = state.corpus().dir_path().clone();
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
        rename(&options.dirs()[0], temp)?;
        rename(corpus_dir, &options.dirs()[0])?;
    }

    mgr.send_exiting()
}
