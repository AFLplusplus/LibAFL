//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use core::time::Duration;
use std::{env, path::PathBuf};

use libafl::{
    bolts::{shmem::StdShMem, tuples::tuple_list},
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    events::{setup_new_llmp_broker, setup_restarting_mgr, setup_restarting_mgr_client},
    executors::{inprocess::InProcessExecutor, Executor, ExitKind, TimeoutExecutor},
    feedbacks::{
        CrashFeedback, MapFeedback, MaxMapFeedback, MaxReducer, TimeFeedback, TimeoutFeedback,
    },
    fuzzer::{Fuzzer, HasCorpusScheduler, StdFuzzer},
    inputs::{BytesInput, Input},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, launcher, StdRand},
    Error,
};
use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, EDGES_MAP, MAX_EDGES_NUM};
extern crate clap;
use clap::{load_yaml, App};
/// The main fn, no_mangle as it is a C main
#[no_mangle]
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();
    let yaml = load_yaml!("clap-config.yaml");
    let matches = App::from(yaml).get_matches();

    let cores = matches.value_of("cores").unwrap().to_string();
    //println!("{:?}", args);
    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let broker_args = FnArgs {
        corpus_dirs: vec![PathBuf::from("./corpus")],
        objective_dir: PathBuf::from("./crashes"),
        broker_port: 1337,
    };
    let client_args = FnArgs {
        corpus_dirs: vec![PathBuf::from("./corpus")],
        objective_dir: PathBuf::from("./crashes"),
        broker_port: 1337,
    };
    #[cfg(unix)]
    launcher(in_broker, in_client, 1337, client_args, cores).unwrap();

    #[cfg(not(unix))]
    in_client(
        corpus_dirs: vec![PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        1337,
    )
    .unwrap();
}

struct FnArgs {
    corpus_dirs: Vec<PathBuf>,
    objective_dir: PathBuf,
    broker_port: u16,
}
fn in_broker(broker_port: u16) -> Result<(), Error> {
    let stats = SimpleStats::new(|s| println!("{}", s));
    setup_new_llmp_broker::<
        BytesInput,
        State<
            InMemoryCorpus<BytesInput>,
            (
                MapFeedback<u8, MaxReducer<u8>, HitcountsMapObserver<StdMapObserver<u8>>>,
                (TimeFeedback, ()),
            ),
            BytesInput,
            (CrashFeedback, (TimeoutFeedback, ())),
            StdRand,
            OnDiskCorpus<BytesInput>,
        >,
        StdShMem,
        _,
    >(stats, broker_port)
}
fn in_client(fn_args: FnArgs) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        match setup_restarting_mgr_client::<_, _, StdShMem, _>(stats, fn_args.broker_port) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return Ok(());
                }
                _ => {
                    panic!("Failed to setup the restarter: {}", err);
                }
            },
        };

    // Create an observation channel using the coverage map
    let edges_observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::new("edges", &mut EDGES_MAP, MAX_EDGES_NUM)
    });

    // If not restarting, create a State from scratch
    let objective_dir = fn_args.objective_dir;
    let mut state = state.unwrap_or_else(|| {
        State::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Feedbacks to rate the interestingness of an input
            tuple_list!(
                MaxMapFeedback::new_with_observer_track(&edges_observer, true, false),
                TimeFeedback::new()
            ),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // Feedbacks to recognize an input as solution
            tuple_list!(CrashFeedback::new(), TimeoutFeedback::new()),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Create a PNG dictionary if not existing
    if state.metadata().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::new(vec![
            vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
            "IHDR".as_bytes().to_vec(),
            "IDAT".as_bytes().to_vec(),
            "PLTE".as_bytes().to_vec(),
            "IEND".as_bytes().to_vec(),
        ]));
    }

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let stage = StdMutationalStage::new(mutator);

    // A fuzzer with just one stage and a minimization+queue policy to get testcasess from the corpus
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |buf: &[u8]| {
        libfuzzer_test_one_input(buf);
        ExitKind::Ok
    };

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            "in-process(edges,time)",
            &mut harness,
            tuple_list!(edges_observer, TimeObserver::new("time")),
            &mut state,
            &mut restarting_mgr,
        )?,
        // 10 seconds timeout
        Duration::new(10, 0),
    );

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if libfuzzer_initialize(&args) == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(
                &mut executor,
                &mut restarting_mgr,
                &scheduler,
                &fn_args.corpus_dirs,
            )
            .expect(&format!(
                "Failed to load initial corpus at {:?}",
                &fn_args.corpus_dirs
            ));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut state, &mut executor, &mut restarting_mgr, &scheduler)?;

    // Never reached
    Ok(())
}
