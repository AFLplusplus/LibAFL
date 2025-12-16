//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for `stb_image`.
use std::io::{self, Write};
use std::{
    env, fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use clap::{self, Parser};
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{
        EventFirer, EventReceiver, EventRestarter, HasEventManagerId,
        ProgressReporter, SendExiting,
    },
    executors::{
        command::CommandConfigurator, inprocess::InProcessExecutor, ExitKind, HasTimeout,
        ShadowExecutor,
    },
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{
        havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator,
        token_mutations::I2SRandReplace,
    },
    observers::{
        concolic::{
            serialization_format::{DEFAULT_ENV_NAME, DEFAULT_SIZE},
            ConcolicObserver,
        },
        CanTrack, TimeObserver,
    },
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{
        ConcolicTracingStage, ShadowTracingStage, SimpleConcolicMutationalStage,
        StdMutationalStage, TracingStage,
    },
    state::{HasCorpus, StdState},
    Error,
};

#[cfg(feature = "restarting")]
use libafl::events::{EventConfig, Launcher};
#[cfg(not(feature = "restarting"))]
use libafl::events::SimpleEventManager;

use libafl_bolts::{
    core_affinity::Cores,
    current_nanos,
    ownedref::OwnedSlice,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Handled},
    AsSlice, AsSliceMut,
};

type FuzzerState =
    StdState<InMemoryCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CmpLogObserver,
};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Parser)]
struct Opt {
    /// This node should do concolic tracing + solving instead of traditional fuzzing
    #[arg(short, long)]
    concolic: bool,
}

#[allow(clippy::too_many_arguments)]
fn fuzz_task<EM>(
    state: Option<FuzzerState>,
    mut mgr: EM,
    corpus_dirs: &[PathBuf],
    objective_dir: PathBuf,
    concolic: bool,
) -> Result<(), Error>
where
    EM: EventFirer<BytesInput, FuzzerState>
        + EventRestarter<FuzzerState>
        + HasEventManagerId
        + ProgressReporter<FuzzerState>
        + EventReceiver<BytesInput, FuzzerState>
        + SendExiting,
{
    println!("DEBUG: Manager configured");

    // Create an observation channel using the coverage map
    // We don't use the hitcounts (see the Cargo.toml, we use pcguard_edges)
    let edges_observer = unsafe { std_edges_map_observer("edges").track_indices() };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir.clone()).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    println!("We're a client, let's fuzz :)");

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe {
            libfuzzer_test_one_input(buf);
        }
        ExitKind::Ok
    };

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = ShadowExecutor::new(
        InProcessExecutor::new(
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?,
        tuple_list!(cmplog_observer),
    );

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, corpus_dirs)
            .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", corpus_dirs));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // Setup a tracing stage in which we log comparisons
    let tracing = ShadowTracingStage::new();

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));

    // Setup a basic mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mutational = StdMutationalStage::new(mutator);

    if concolic {
        // The shared memory for the concolic runtime to write its trace to
        let mut concolic_shmem = StdShMemProvider::new()
            .unwrap()
            .new_shmem(DEFAULT_SIZE)
            .unwrap();
        // # Safety
        // The only place we access this env from
        unsafe {
            concolic_shmem.write_to_env(DEFAULT_ENV_NAME).unwrap();
        }

        // The concolic observer observers the concolic shared memory map.
        let concolic_observer = ConcolicObserver::new("concolic", concolic_shmem.as_slice_mut());
        let concolic_ref = concolic_observer.handle();

        // The order of the stages matter!
        let mut stages = tuple_list!(
            // Create a concolic trace
            ConcolicTracingStage::new(
                TracingStage::new(MyCommandConfigurator.into_executor(
                    tuple_list!(concolic_observer),
                    None,
                    None
                ),),
                concolic_ref,
            ),
            // Use the concolic trace for z3-based solving
            SimpleConcolicMutationalStage::new(),
        );

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    } else {
        // The order of the stages matter!
        let mut stages = tuple_list!(tracing, i2s, mutational);

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    }
    Ok(())
}

pub fn main() {
    let opt = Opt::parse();
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }

    let _ = fs::remove_file("cur_input");
    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    io::stdout().flush().unwrap();
    let _port = env::var("BROKER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1337);

    let corpus_dirs = [PathBuf::from("./corpus")];
    let objective_dir = PathBuf::from("./crashes");

    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    let _cores = Cores::from(vec![0]);

    #[cfg(feature = "restarting")]
    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new().expect("Failed to init shared memory"))
        .broker_port(_port)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .cores(&_cores)
        .run_client(|state: Option<FuzzerState>, mgr, _client_desc| {
            fuzz_task(
                state,
                mgr,
                &corpus_dirs,
                objective_dir.clone(),
                opt.concolic,
            )
        })
        .build()
        .launch()
    {
        Ok(_) => (),
        Err(Error::ShuttingDown) => (),
        Err(e) => panic!("Launcher failed: {e}"),
    }

    #[cfg(not(feature = "restarting"))]
    {
        let mgr = SimpleEventManager::new(monitor);
        if let Err(e) = fuzz_task(None, mgr, &corpus_dirs, objective_dir.clone(), opt.concolic) {
            panic!("Fuzzer failed: {e}");
        }
    }
}

#[derive(Default, Debug)]
pub struct MyCommandConfigurator;

impl CommandConfigurator<Child> for MyCommandConfigurator {
    fn spawn_child(&mut self, target_bytes: OwnedSlice<'_, u8>) -> Result<Child, Error> {
        fs::write("cur_input", target_bytes.as_slice())?;

        Ok(Command::new("./target_symcc.out")
            .arg("cur_input")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("SYMCC_INPUT_FILE", "cur_input")
            .spawn()
            .expect("failed to start process"))
    }
}

impl HasTimeout for MyCommandConfigurator {
    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
}
