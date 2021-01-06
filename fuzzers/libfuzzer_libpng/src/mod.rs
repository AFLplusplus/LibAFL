#[macro_use]
extern crate clap;

use clap::{App, Arg};
use std::{env, path::PathBuf, process::Command};

use afl::{
    corpus::{Corpus, InMemoryCorpus},
    engines::{Engine, Fuzzer, State, StdFuzzer},
    events::{
        llmp::LlmpReceiver,
        llmp::LlmpSender,
        shmem::{AflShmem, ShMem},
        EventManager, LlmpEventManager, SimpleStats,
    },
    executors::{
        inmemory::{deserialize_state_corpus, serialize_state_corpus, InMemoryExecutor},
        Executor, ExitKind,
    },
    feedbacks::MaxMapFeedback,
    generators::RandPrintablesGenerator,
    inputs::BytesInput,
    mutators::{scheduled::HavocBytesMutator, HasMaxSize},
    observers::StdMapObserver,
    stages::mutational::StdMutationalStage,
    tuples::tuple_list,
    utils::StdRand,
    AflError,
};

/// The llmp connection from the actual fuzzer to the process supervising it
const ENV_FUZZER_SENDER: &str = &"_AFL_ENV_FUZZER_SENDER";
const ENV_FUZZER_RECEIVER: &str = &"_AFL_ENV_FUZZER_RECEIVER";
/// The llmp (2 way) connection from a fuzzer to the broker (broadcasting all other fuzzer messages)
const ENV_FUZZER_BROKER_CLIENT: &str = &"_AFL_ENV_FUZZER_BROKER_CLIENT";

/// The name of the coverage map observer, to find it again in the observer list
const NAME_COV_MAP: &str = "cov_map";

/// We will interact with a c++ target, so use external c functionality
extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // afl_libfuzzer_init calls LLVMFUzzerInitialize()
    fn afl_libfuzzer_init() -> i32;

    static __lafl_edges_map: *mut u8;
    static __lafl_cmp_map: *mut u8;
    static __lafl_max_edges_size: u32;
}

/// The wrapped harness function, calling out to the llvm-style libfuzzer harness
fn harness<I>(_executor: &dyn Executor<I>, buf: &[u8]) -> ExitKind {
    unsafe {
        LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len());
    }
    ExitKind::Ok
}

/// The actual fuzzer
fn fuzz(input: Option<Vec<PathBuf>>, broker_port: u16) -> Result<(), AflError> {
    let mut rand = StdRand::new(0);
    let mut generator = RandPrintablesGenerator::new(32);
    let stats = SimpleStats::new(|s| println!("{}", s));
    let mut mgr;

    // We start ourself as child process to actually fuzz
    if std::env::var(ENV_FUZZER_SENDER).is_err() {
        // We are either the broker, or the parent of the fuzzing instance
        mgr = LlmpEventManager::new_on_port_std(broker_port, stats.clone())?;
        if mgr.is_broker() {
            // Yep, broker. Just loop here.
            println!("Doing broker things. Run this tool again to start fuzzing in a client.");
            mgr.broker_loop()?;
        } else {
            // we are one of the fuzzing instances. Let's launch the fuzzer.

            // First, store the mgr to an env so the client can use it
            mgr.to_env(ENV_FUZZER_BROKER_CLIENT);

            // First, create a channel from the fuzzer (sender) to us (receiver) to report its state for restarts.
            let sender = LlmpSender::new(0, false)?;
            let receiver = LlmpReceiver::on_existing_map(
                AflShmem::clone_ref(&sender.out_maps.last().unwrap().shmem)?,
                None,
            )?;
            // Store the information to a map.
            sender.to_env(ENV_FUZZER_SENDER)?;
            receiver.to_env(ENV_FUZZER_RECEIVER)?;

            loop {
                dbg!("Spawning next client");
                Command::new(env::current_exe()?)
                    .current_dir(env::current_dir()?)
                    .args(env::args())
                    .status()?;
            }
        }
    }

    println!("We're a client, let's fuzz :)");

    // We are the fuzzing instance, first, connect to all channels.
    // Mgr to send and receive msgs from/to all other fuzzer instances
    mgr = LlmpEventManager::<BytesInput, _, _>::existing_client_from_env_std(
        ENV_FUZZER_BROKER_CLIENT,
        stats,
    )?;
    // A sender and a receiver for single communication
    let mut receiver = LlmpReceiver::<AflShmem>::on_existing_from_env(ENV_FUZZER_RECEIVER)?;
    let mut sender = LlmpSender::<AflShmem>::on_existing_from_env(ENV_FUZZER_SENDER)?;

    let edges_observer =
        StdMapObserver::new_from_ptr(&NAME_COV_MAP, unsafe { __lafl_edges_map }, unsafe {
            __lafl_max_edges_size as usize
        });

    // Call LLVMFUzzerInitialize() if present.
    unsafe {
        if afl_libfuzzer_init() == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }
    }

    // If we're restarting, deserialize the old corpus.
    let (mut state, mut corpus) = match receiver.recv_buf()? {
        None => {
            // Initial execution, read or generate initial state, corpus, and feedbacks
            let edges_feedback = MaxMapFeedback::new_with_observer(&NAME_COV_MAP, &edges_observer);
            let state = State::new(tuple_list!(edges_feedback));
            let corpus = InMemoryCorpus::new();
            (state, corpus)
        }
        // Restoring from a previous run, deserialize state and corpus.
        Some((_sender, _tag, msg)) => deserialize_state_corpus(&msg)?,
    };
    // We reset the sender, the next sender and receiver (after crash) will reuse the page from the initial message.
    unsafe { sender.reset_last_page() };

    // Create the engine
    let executor = InMemoryExecutor::<_, _, _, LlmpEventManager<_, _, _>, _, _>::new(
        "Libfuzzer",
        harness,
        tuple_list!(edges_observer),
        Box::new(move |exit_kind, input, state, corpus, mgr| {
            match exit_kind {
                ExitKind::Timeout => mgr.timeout(input).expect(&format!(
                    "Error sending Timeout event for input {:?}",
                    input
                )),
                ExitKind::Crash => mgr
                    .crash(input)
                    .expect(&format!("Error sending crash event for input {:?}", input)),
                _ => (),
            }
            let state_corpus_serialized = serialize_state_corpus(state, corpus).unwrap();
            sender.send_buf(0x1, &state_corpus_serialized).unwrap();
        }),
        &state,
        &corpus,
        &mut mgr,
    );

    let mut engine = Engine::new(executor);

    // in case the corpus is empty (on first run), reset
    if corpus.count() < 1 {
        match input {
            Some(x) => state
                .load_initial_inputs(&mut corpus, &mut generator, &mut engine, &mut mgr, &x)
                .expect(&format!("Failed to load initial corpus at {:?}", &x)),
            None => (),
        }
        println!("We imported {} inputs from disk.", corpus.count());
    }
    if corpus.count() < 1 {
        println!("Generating random inputs");
        state
            .generate_initial_inputs(
                &mut rand,
                &mut corpus,
                &mut generator,
                &mut engine,
                &mut mgr,
                4,
            )
            .expect("Failed to generate initial inputs");
        println!("We generated {} inputs.", corpus.count());
    }

    let mut mutator = HavocBytesMutator::new_default();
    mutator.set_max_size(4096);

    let stage = StdMutationalStage::new(mutator);
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    fuzzer.fuzz_loop(&mut rand, &mut state, &mut corpus, &mut engine, &mut mgr)
}

/// The main fn, parsing parameters, and starting the fuzzer
pub fn main() {
    let matches = App::new("libAFLrs fuzzer harness")
        .about("libAFLrs fuzzer harness help options.")
        .arg(
            Arg::with_name("port")
                .short("p")
                .value_name("PORT")
                .takes_value(true)
                .help("Broker TCP port to use."),
        )
        .arg(
            Arg::with_name("dictionary")
                .short("x")
                .value_name("DICTIONARY")
                .takes_value(true)
                .multiple(true)
                .help("Dictionary file to use, can be specified multiple times."),
        )
        .arg(
            Arg::with_name("statstime")
                .short("T")
                .value_name("STATSTIME")
                .takes_value(true)
                .help("How often to print statistics in seconds [default: 5, disable: 0]"),
        )
        .arg(Arg::with_name("workdir")
                               .help("Where to write the corpus, also reads the data on start. If more than one is supplied the first will be the work directory, all others will just be initially read from.")
                                .multiple(true)
                                .value_name("WORKDIR")
                               )
        .get_matches();

    let _ = value_t!(matches, "statstime", u32).unwrap_or(5);
    let broker_port = value_t!(matches, "port", u16).unwrap_or(1337);

    let workdir = if matches.is_present("workdir") {
        matches.value_of("workdir").unwrap().to_string()
    } else {
        env::current_dir().unwrap().to_string_lossy().to_string()
    };

    let mut dictionary: Option<Vec<PathBuf>> = None;

    if matches.is_present("dictionary") {
        dictionary = Some(values_t!(matches, "dictionary", PathBuf).unwrap_or_else(|e| e.exit()));
    }

    let mut input: Option<Vec<PathBuf>> = None;
    if matches.is_present("workdir") {
        input = Some(values_t!(matches, "workdir", PathBuf).unwrap_or_else(|e| e.exit()));
    }

    if dictionary != None || input != None {
        println!("Information: the first process started is the broker and only processes the \'-p PORT\' option if present.");
    }

    println!("Workdir: {:?}", workdir);

    fuzz(Some(vec![PathBuf::from("./in1")]), broker_port).expect("An error occurred while fuzzing");
    //fuzz(input, broker_port).expect("An error occurred while fuzzing");
}
