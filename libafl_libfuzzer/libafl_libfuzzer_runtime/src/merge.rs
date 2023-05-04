use std::{env::temp_dir, ffi::c_int, fmt::Debug, fs};

use libafl::{
    bolts::{
        rands::{Rand, RandomSeed, StdRand},
        shmem::{ShMem, ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Named},
        AsIter, AsMutSlice, AsSlice,
    },
    corpus::{Corpus, CorpusMinimizer, InMemoryCorpus, OnDiskCorpus, StdCorpusMinimizer},
    events::SimpleEventManager,
    executors::{inprocess::TimeoutInProcessForkExecutor, ExitKind},
    feedbacks::{MapFeedbackMetadata, MaxMapFeedback},
    inputs::{BytesInput, HasTargetBytes, UsesInput},
    observers::{
        HitcountsIterableMapObserver, MapObserver, MultiMapObserver, Observer, StdMapObserver,
        TimeObserver,
    },
    schedulers::QueueScheduler,
    state::{HasCorpus, HasNamedMetadata, HasRand, StdState},
    Error, StdFuzzer,
};
use libafl_targets::COUNTERS_MAPS;
use serde::{Deserialize, Serialize};

use crate::options::LibfuzzerOptions;

#[derive(Serialize, Deserialize, Debug)]
struct EdgeCopyObserver<O> {
    inner: O,
    #[serde(skip, default = "core::ptr::null_mut")]
    shmem: *mut u8,
}

impl<O> Named for EdgeCopyObserver<O>
where
    O: Named,
{
    fn name(&self) -> &str {
        self.inner.name()
    }
}

impl<O, S> Observer<S> for EdgeCopyObserver<O>
where
    O: MapObserver<Entry = u8> + for<'a> AsIter<'a, Item = u8> + Observer<S> + Named + Debug,
    S: UsesInput,
{
    fn post_exec_child(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.inner.post_exec(state, input, exit_kind)?;
        for (i, e) in self
            .inner
            .as_iter()
            .zip(unsafe { core::slice::from_raw_parts_mut(self.shmem, self.inner.usable_count()) })
        {
            *e = *i;
        }
        Ok(())
    }
}

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

    let mut shmem_provider = StdShMemProvider::new()?;

    let edges = unsafe { &mut COUNTERS_MAPS };
    let edges_observer = HitcountsIterableMapObserver::new(MultiMapObserver::new("edges", edges));

    let mut shmem = shmem_provider.new_shmem(edges_observer.usable_count())?;

    let parent_edges = unsafe {
        StdMapObserver::from_mut_ptr(
            "parent-edges",
            shmem.as_mut_slice().as_mut_ptr(),
            shmem.len(),
        )
    };
    let copier = EdgeCopyObserver {
        inner: edges_observer,
        shmem: shmem.as_mut_slice().as_mut_ptr(),
    };

    let time = TimeObserver::new("time");

    let cmin = StdCorpusMinimizer::new(&parent_edges);

    let mut map_feedback = MaxMapFeedback::new(&parent_edges);
    let map_feedback_name = map_feedback.name().to_string();

    let observers = tuple_list!(copier, parent_edges, time);

    let mut state = StdState::new(
        rand,
        OnDiskCorpus::new(corpus_dir.clone()).unwrap(),
        InMemoryCorpus::new(),
        &mut map_feedback,
        &mut (), // no objectives
    )?;

    let mut mgr = SimpleEventManager::printing();

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

    let mut executor = TimeoutInProcessForkExecutor::new(
        &mut harness,
        observers,
        &mut fuzzer,
        &mut state,
        &mut mgr,
        options.timeout(),
        shmem_provider,
    )?;

    state.load_initial_inputs_forced(&mut fuzzer, &mut executor, &mut mgr, options.dirs())?;

    let edge_meta = state
        .named_metadata()
        .get::<MapFeedbackMetadata<u8>>(&map_feedback_name)
        .unwrap();
    let edges_max = edge_meta.history_map.len();
    let edges = edges_max - bytecount::count(&edge_meta.history_map, 0);

    println!(
        "Loaded {} initial inputs with {}/{} edges; minimizing...",
        state.corpus().count(),
        edges,
        edges_max
    );

    cmin.minimize(&mut fuzzer, &mut executor, &mut mgr, &mut state)?;

    println!(
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

    Ok(())
}
