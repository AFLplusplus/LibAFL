#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate clap;
extern crate alloc;

use clap::{App, Arg};
use std::env;

use afl::corpus::InMemoryCorpus;
use afl::engines::Engine;
use afl::engines::Fuzzer;
use afl::engines::State;
use afl::engines::StdFuzzer;
use afl::events::{LlmpEventManager, SimpleStats};
use afl::executors::inmemory::InMemoryExecutor;
use afl::executors::{Executor, ExitKind};
use afl::feedbacks::MaxMapFeedback;
use afl::generators::RandPrintablesGenerator;
use afl::mutators::scheduled::HavocBytesMutator;
use afl::mutators::HasMaxSize;
use afl::observers::StdMapObserver;
use afl::stages::mutational::StdMutationalStage;
use afl::tuples::tuple_list;
use afl::utils::StdRand;

extern "C" {
    /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    /// int LLVMFuzzerInitialize(int argc, char **argv)
    fn afl_libfuzzer_init(argc: u32, argv: *const *const u8) -> i32;

    static __lafl_edges_map: *mut u8;
    static __lafl_cmp_map: *mut u8;
    static __lafl_max_edges_size: u32;
}

fn harness<I>(_executor: &dyn Executor<I>, buf: &[u8]) -> ExitKind {
    unsafe {
        LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len());
    }
    ExitKind::Ok
}

const NAME_COV_MAP: &str = "cov_map";

#[no_mangle]
pub extern "C" fn afl_libfuzzer_main() {
    let matches = App::new("libAFLrs fuzzer harness")
        .about("libAFLrs fuzzer harness help options.")
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

    let statstime = value_t!(matches, "statstime", u32).unwrap_or(5);

    let workdir = if matches.is_present("workdir") {
        matches.value_of("workdir").unwrap().to_string()
    } else {
        env::current_dir().unwrap().to_string_lossy().to_string()
    };

    let mut dictionary: Option<Vec<String>> = None;

    if matches.is_present("dictionary") {
        dictionary = Some(values_t!(matches, "dictionary", String).unwrap_or_else(|e| e.exit()));
    }

    let mut input: Option<Vec<String>> = None;
    if matches.is_present("workdir") {
        input = Some(values_t!(matches, "workdir", String).unwrap_or_else(|e| e.exit()));
    }

    // debug prints

    println!("workdir: {}", workdir);

    if dictionary != None {
        for file in dictionary.unwrap() {
            println!("dic: {}", file);
        }
    }

    if input != None {
        for indir in input.clone().unwrap() {
            println!("in: {}", indir);
        }
    }

    // original code

    let mut rand = StdRand::new(0);
    let mut corpus = InMemoryCorpus::new();
    let mut generator = RandPrintablesGenerator::new(32);

    let stats = SimpleStats::new(|s| println!("{}", s));
    let mut mgr = LlmpEventManager::new_on_port(1337, stats).unwrap();
    if mgr.is_broker() {
        println!("Doing broker things.");
        mgr.broker_loop().unwrap();
    }
    println!("We're a client, let's fuzz :)");

    //    unsafe {

    //        if afl_libfuzzer_init(...) == -1 {

    //            println("Warning: LLVMFuzzerInitialize failed with -1")

    //        }

    //    }

    let edges_observer =
        StdMapObserver::new_from_ptr(&NAME_COV_MAP, unsafe { __lafl_edges_map }, unsafe {
            __lafl_max_edges_size as usize
        });
    let edges_feedback = MaxMapFeedback::new_with_observer(&NAME_COV_MAP, &edges_observer);

    let executor = InMemoryExecutor::new("Libfuzzer", harness, tuple_list!(edges_observer));
    let mut state = State::new(tuple_list!(edges_feedback));

    let mut engine = Engine::new(executor);

    if input != None {
        state
            .load_initial_inputs(
                &mut corpus,
                &mut generator,
                &mut engine,
                &mut mgr,
                input.unwrap(),
            )
            .expect("Failed to load initial corpus");
    } else {
        state
            .generate_initial_inputs(
                &mut rand,
                &mut corpus,
                &mut generator,
                &mut engine,
                &mut mgr,
                4,
            )
            .expect("Failed to load initial inputs");
    }

    let mut mutator = HavocBytesMutator::new_default();
    mutator.set_max_size(4096);

    let stage = StdMutationalStage::new(mutator);
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    fuzzer
        .fuzz_loop(&mut rand, &mut state, &mut corpus, &mut engine, &mut mgr)
        .expect("Fuzzer fatal error");
    #[cfg(feature = "std")]
    println!("OK");
}
