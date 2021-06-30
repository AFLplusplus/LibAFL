use concolic::{Message, MessageFileReader};
use core::time::Duration;
use libafl::feedbacks::{EagerOrFeedback, Feedback};
use libafl::inputs::Input;
use libafl::observers::ObserversTuple;
use libafl::state::HasMetadata;
use libafl::Error;
use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        shmem::{ShMem, ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Named},
    },
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler, Testcase},
    events::SimpleEventManager,
    executors::{ExitKind, HasExecHooks, InProcessExecutor},
    feedbacks::{CrashFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{Observer, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
    stats::SimpleStats,
};
use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    os::unix::prelude::ExitStatusExt,
    path::PathBuf,
    process::{Command, Stdio},
    thread::sleep,
    time::Instant,
};

fn run_target<I: Input + HasTargetBytes>(input: &I) -> ExitKind {
    let mut command = Command::new("../if");
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let start_time = Instant::now();
    let mut child = command.spawn().expect("failed to start process");
    let mut stdin = child.stdin.as_ref().unwrap();
    if let Err(e) = stdin.write_all(input.target_bytes().as_slice()) {
        todo!("handle error {}", e);
    }

    loop {
        match child.try_wait().expect("waiting on child failed") {
            Some(exit_status) => {
                if let Some(signal) = exit_status.signal() {
                    // for reference: https://www.man7.org/linux/man-pages/man7/signal.7.html
                    match signal {
                        9 /* SIGKILL */ => {
                            // we assume the child was killed due to OOM
                            return ExitKind::Oom;
                        }
                        _ => {return ExitKind::Crash;}
                    }
                } else {
                    return ExitKind::Ok;
                }
            }
            None => {
                if start_time.elapsed() > Duration::from_secs(5) {
                    return ExitKind::Timeout;
                }
                sleep(Duration::from_millis(1));
            }
        }
    }
}

/// A state metadata holding a list of values logged from comparisons
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ConcolicMetadata {
    /// Constraints data
    buffer: Vec<u8>,
}

impl ConcolicMetadata {
    pub fn iter_messages(&self) -> impl Iterator<Item = (NonZeroUsize, Message)> + '_ {
        let mut parser = MessageFileReader::new_from_buffer(&self.buffer)
            .expect("constructing an in-memory reader should never fail");
        std::iter::from_fn(move || parser.next_message()).flatten()
    }
}

libafl::impl_serdeany!(ConcolicMetadata);

/// A standard [`ConcolicObserver`] observer
#[derive(Serialize, Deserialize, Debug)]
pub struct ConcolicObserver<'map> {
    #[serde(skip)]
    map: &'map [u8],
    name: String,
}

impl<'map> Observer for ConcolicObserver<'map> {}

impl<'map> ConcolicObserver<'map> {
    pub fn create_metadata_from_current_map(&self) -> ConcolicMetadata {
        let reader = MessageFileReader::new_from_length_prefixed_buffer(self.map)
            .expect("constructing the message reader from a memory buffer should not fail");
        ConcolicMetadata {
            buffer: reader.get_buffer().to_vec(),
        }
    }
}

impl<'map, EM, I: Input, S: HasMetadata, Z> HasExecHooks<EM, I, S, Z> for ConcolicObserver<'map> {
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        // Add a copy of the trace to the input metadata
        Ok(())
    }
}

impl<'map> Named for ConcolicObserver<'map> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<'map> ConcolicObserver<'map> {
    /// Creates a new [`ConcolicObserver`] with the given name and map.
    #[must_use]
    pub fn new(name: String, map: &'map [u8]) -> Self {
        Self { name, map }
    }
}

struct ConcolicFeedback {
    name: String,
    metadata: Option<ConcolicMetadata>,
}

impl ConcolicFeedback {
    pub fn from_observer(observer: &ConcolicObserver) -> Self {
        Self {
            name: observer.name().to_owned(),
            metadata: None,
        }
    }
}

impl Named for ConcolicFeedback {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<I: Input, S: HasMetadata> Feedback<I, S> for ConcolicFeedback {
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: libafl::events::EventFirer<I, S>,
        OT: ObserversTuple,
    {
        self.metadata = observers
            .match_name::<ConcolicObserver>(&self.name)
            .map(|o| o.create_metadata_from_current_map());
        Ok(true)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        if let Some(metadata) = self.metadata.take() {
            for (_id, _expression_type) in metadata.iter_messages() {
                println!("{} -> {:?}", _id, _expression_type);
            }
            _testcase.metadata_mut().insert(metadata);
        }
        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}

#[allow(clippy::similar_names)]
pub fn main() {
    const MAP_SIZE: usize = 1024 * 1024 * 1024;
    //Coverage map shared between observer and executor
    let mut shmem = StdShMemProvider::new().unwrap().new_map(MAP_SIZE).unwrap();
    //let the forkserver know the shmid
    shmem.write_to_env("SHARED_MEMORY_MESSAGES").unwrap();
    // Create an observation channel using the signals map
    /*let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
        "shared_mem",
        &mut shmem_map,
    )); */

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let concolic_observer = ConcolicObserver::new("concolic".to_string(), shmem.map_mut());

    // The state of the edges feedback.
    //let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // The state of the edges feedback for crashes.
    //let objective_state = MapFeedbackState::new("crash_edges", MAP_SIZE);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let feedback = TimeFeedback::new_with_observer(&time_observer);

    let feedback_conc = ConcolicFeedback::from_observer(&concolic_observer);

    let feedback = EagerOrFeedback::new(feedback, feedback_conc);

    // A feedback to choose if an input is a solution or not
    // We want to do the same crash deduplication that AFL does
    let objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::<BytesInput>::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // They are the data related to the feedbacks that you want to persist in the State.
        tuple_list!(),
    );

    // The Stats trait define how the fuzzer stats are reported to the user
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(stats);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = QueueCorpusScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut target = run_target;
    // Create the executor for the forkserver
    let mut executor = InProcessExecutor::new(
        &mut target,
        tuple_list!(time_observer, concolic_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .unwrap();

    state
        .corpus_mut()
        .add(Testcase::new(BytesInput::new(vec![1, 2, 3, 4])))
        .unwrap();

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
