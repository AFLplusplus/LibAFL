//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

#[macro_use]
extern crate clap;

use clap::{App, Arg};
use std::{env, path::PathBuf, process::Command};

use afl::{
    corpus::{Corpus, InMemoryCorpus},
    events::setup_restarting_state,
    events::{LlmpEventManager, SimpleStats},
    executors::{inprocess::InProcessExecutor, Executor, ExitKind},
    feedbacks::MaxMapFeedback,
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, Input},
    mutators::{scheduled::HavocBytesMutator, HasMaxSize},
    observers::StdMapObserver,
    shmem::{AflShmem, ShMem},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, State},
    tuples::tuple_list,
    utils::StdRand,
    AflError, Fuzzer, StdFuzzer,
};

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
fn harness<E, I>(_executor: &E, buf: &[u8]) -> ExitKind
where
    E: Executor<I>,
    I: Input,
{
    unsafe {
        LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len());
    }
    ExitKind::Ok
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

/// The actual fuzzer
fn fuzz(input: Option<Vec<PathBuf>>, broker_port: u16) -> Result<(), AflError> {
    let mut rand = StdRand::new(0);
    /// TODO: Don't the stats need to be serialized, too?
    let stats = SimpleStats::new(|s| println!("{}", s));

    let mut mgr = LlmpEventManager::new_on_port_std(stats, broker_port)?;
    if mgr.is_broker() {
        // Yep, broker. Just loop here.
        println!("Doing broker things. Run this tool again to start fuzzing in a client.");
        mgr.broker_loop()?;
    }

    let edges_observer =
        StdMapObserver::new_from_ptr(&NAME_COV_MAP, unsafe { __lafl_edges_map }, unsafe {
            __lafl_max_edges_size as usize
        });

    let mut mutator = HavocBytesMutator::new_default();
    mutator.set_max_size(4096);
    let stage = StdMutationalStage::new(mutator);
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    // The restarting state will spawn the same process again as child, then restartet it each time it crashes.
    let (state_opt, mut restarting_mgr) =
        setup_restarting_state(&mut mgr).expect("Failed to setup the restarter".into());
    let mut state = match state_opt {
        Some(s) => s,
        None => State::new(
            InMemoryCorpus::new(),
            tuple_list!(MaxMapFeedback::new_with_observer(
                &NAME_COV_MAP,
                &edges_observer
            )),
        ),
    };

    println!("We're a client, let's fuzz :)");

    // Create the executor
    let mut executor = InProcessExecutor::new(
        "Libfuzzer",
        harness,
        tuple_list!(edges_observer),
        &mut state,
        &mut restarting_mgr,
    );

    // The actual target run starts here.

    // Call LLVMFUzzerInitialize() if present.
    unsafe {
        if afl_libfuzzer_init() == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }
    }

    // in case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        match input {
            Some(x) => state
                .load_initial_inputs(&mut executor, &mut restarting_mgr, &x)
                .expect(&format!("Failed to load initial corpus at {:?}", &x)),
            None => (),
        }
        println!("We imported {} inputs from disk.", state.corpus().count());
    }
    /*
    if state.corpus().count() < 1 {
        println!("Generating random inputs");
        let mut generator = RandPrintablesGenerator::new(32);
        state
            .generate_initial_inputs(&mut rand, &mut executor, &mut generator, &mut restarting_mgr, 4)
            .expect("Failed to generate initial inputs");
        println!("We generated {} inputs.", state.corpus().count());
    }
    */

    fuzzer.fuzz_loop(&mut rand, &mut executor, &mut state, &mut restarting_mgr)
}
