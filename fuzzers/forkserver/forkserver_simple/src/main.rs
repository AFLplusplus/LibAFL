use std::{fs, io::Read, path::PathBuf};

use libafl::{
    NopInputFilter, StdFuzzerBuilder,
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::ForkserverExecutor,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Evaluator, Fuzzer},
    inputs::{InputEncoder, NaiveTokenizer, TokenInputEncoderDecoder},
    monitors::SimpleMonitor,
    mutators::{encoded_mutations::encoded_mutations, scheduled::HavocScheduledMutator},
    observers::{HitcountsMapObserver, StdMapObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    AsSliceMut, StdTargetArgs,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
// TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
#[allow(static_mut_refs)] // only a problem in nightly
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

pub fn main() {
    let mut tokenizer = NaiveTokenizer::default();
    let mut encoder_decoder = TokenInputEncoderDecoder::new();
    let mut initial_inputs = vec![];
    const MAP_SIZE: usize = 65536;

    let mut shmem_provider = StdShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
    unsafe {
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
    }
    let shmembuf = shmem.as_slice_mut();
    let edges_observer =
        unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmembuf)) };

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

    // Create an observation channel using the signals map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem in nightly
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&edges_observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();
    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let mut mgr = SimpleEventManager::new(monitor);

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
    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    println!("Decoder {:?} ...", &encoder_decoder);

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzerBuilder::new()
        .target_bytes_converter(encoder_decoder)
        .input_filter(NopInputFilter)
        .scheduler(scheduler)
        .feedback(feedback)
        .objective(objective)
        .build();

    // Create the executor for an in-process function with just one observer
    let mut executor = ForkserverExecutor::builder()
        .program("./target")
        .shmem_provider(&mut shmem_provider)
        .coverage_map_size(MAP_SIZE)
        .build(tuple_list!(edges_observer))
        .unwrap();

    // Setup a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::with_max_stack_pow(encoded_mutations(), 2);
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    for input in initial_inputs {
        fuzzer
            .add_input(&mut state, &mut executor, &mut mgr, input)
            .unwrap();
    }

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
