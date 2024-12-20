#[cfg(windows)]
use std::ptr::write_volatile;
use std::{fs, io::Read, path::PathBuf};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::{EncodedInput, InputDecoder, InputEncoder, NaiveTokenizer, TokenInputEncoderDecoder},
    monitors::SimpleMonitor,
    mutators::{encoded_mutations::encoded_mutations, scheduled::StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
// TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
#[allow(static_mut_refs)] // only a problem in nightly
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

/*
/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}
*/

pub fn main() {
    let mut tokenizer = NaiveTokenizer::default();
    let mut encoder_decoder = TokenInputEncoderDecoder::new();
    let mut initial_inputs = vec![];
    let mut decoded_bytes = vec![];

    for entry in fs::read_dir("./corpus").unwrap() {
        let path = entry.unwrap().path();
        let attr = fs::metadata(&path);
        if attr.is_err() {
            continue;
        }
        let attr = attr.unwrap();

        if attr.is_file() && attr.len() > 0 {
            println!("Loading file {:?} ...", &path);
            let mut file = fs::File::open(path).expect("no file found");
            let mut buffer = vec![];
            file.read_to_end(&mut buffer).expect("buffer overflow");
            let input = encoder_decoder
                .encode(&buffer, &mut tokenizer)
                .expect("encoding failed");
            initial_inputs.push(input);
        }
    }

    // The closure that we want to fuzz
    let mut harness = |input: &EncodedInput| {
        decoded_bytes.clear();
        encoder_decoder.decode(input, &mut decoded_bytes).unwrap();
        unsafe {
            println!("{}", std::str::from_utf8_unchecked(&decoded_bytes));
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem in nightly
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are reported to the user
    let monitor = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(monitor);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::with_max_stack_pow(encoded_mutations(), 2);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    println!("Decoder {:?} ...", &encoder_decoder);

    for input in initial_inputs {
        fuzzer
            .add_input(&mut state, &mut executor, &mut mgr, input)
            .unwrap();
    }

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
