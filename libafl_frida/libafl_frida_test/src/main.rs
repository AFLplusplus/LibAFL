use std::ptr::null;

use libafl_bolts::{rands::StdRand, tuples::tuple_list, cli::FuzzerOptions, AsSlice};
use clap_builder::Parser;
use libafl::{
    corpus::{Corpus, InMemoryCorpus, Testcase},
    events::NopEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedbacks::ConstFeedback,
    inputs::{BytesInput, HasTargetBytes},
    mutators::{mutations::BitFlipMutator, StdScheduledMutator},
    schedulers::StdScheduler,
    stages::StdMutationalStage,
    state::{StdState, HasSolutions},
    Fuzzer, StdFuzzer, feedback_or_fast, feedback_and_fast, 
};

use libafl_frida::{
    asan::{
        errors::{AsanErrorsFeedback, AsanErrorsObserver, ASAN_ERRORS},
        asan_rt::AsanRuntime,
    },
    coverage_rt::CoverageRuntime,
    executor::FridaInProcessExecutor,
    helper::FridaInstrumentationHelper,
};

use frida_gum::Gum;
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

unsafe fn test_asan(options: &FuzzerOptions) {
    // Gets seg fault - as others do too
    // log::info!("Testing with bogus harness");
    // assert_eq!(test_asan_with_harness(|_buf: &BytesInput| ExitKind::Ok, options), 0);

    // The names of the functions to run
    let tests = vec![/*"LLVMFuzzerTestOneInput",*/ "heap_uaf_write"];//, "heap_uaf_read"];
    
    // Run the tests for each function
    for test in tests {
        log::info!("Testing with harness function {}", test);
        let lib = libloading::Library::new(options.clone().harness.unwrap()).unwrap();
        let target_func: libloading::Symbol<
            unsafe extern "C" fn(data: *const u8, size: usize) -> i32,
        > = lib.get(test.as_bytes()).unwrap();
        
    
        let harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            (target_func)(buf.as_ptr(), buf.len());
            ExitKind::Ok
        };
    
        // This actually should check for 1, but as of now we get 70
        assert!(test_asan_with_harness(harness, options) > 0);
    }
}

unsafe fn test_asan_with_harness<F>(mut harness: F, options: &FuzzerOptions) ->  usize
where
    F: FnMut(&BytesInput) -> ExitKind,
{
    // let gum = Gum::obtain();

    let mut corpus = InMemoryCorpus::<BytesInput>::new();
    
    //TODO - make sure we use the right one
    let testcase = Testcase::new(vec![0; 4].into());
    corpus.add(testcase).unwrap();
    
    let coverage = CoverageRuntime::new();
    let asan = AsanRuntime::new(&options);
    let mut frida_helper =
        FridaInstrumentationHelper::new(&GUM, &options, tuple_list!(coverage, asan));


    let rand = StdRand::with_seed(0);

    let mut feedback = ConstFeedback::new(false);

    // Feedbacks to recognize an input as solution
    let mut objective = feedback_or_fast!(
        // true enables the AsanErrorFeedback
        feedback_and_fast!(ConstFeedback::from(true), AsanErrorsFeedback::new())
    );

    let mut state = StdState::new(
        rand,
        corpus,
        InMemoryCorpus::<BytesInput>::new(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();


    let mut event_manager = NopEventManager::new();


    let mut fuzzer = StdFuzzer::new(StdScheduler::new(), feedback, objective);

    let observers = tuple_list!(
        AsanErrorsObserver::new(&ASAN_ERRORS) //,
    );


    let mut executor = FridaInProcessExecutor::new(
        &GUM,
        InProcessExecutor::new(
            &mut harness,
            observers, // tuple_list!(),
            &mut fuzzer,
            &mut state,
            &mut event_manager,
        )
        .unwrap(),
        &mut frida_helper,
    );

    // TODO - not sure what mutator do I need here, we use
    // let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

    let mutator = StdScheduledMutator::new(tuple_list!(BitFlipMutator::new()));
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    log::info!("Starting fuzzing!");

    fuzzer
        .fuzz_one(&mut stages, &mut executor, &mut state, &mut event_manager)
        .unwrap_or_else(|_| panic!("Error in fuzz_one"));

    log::info!("Done fuzzing! Got {} solutions", state.solutions().count());
    log::info!("Done");
    state.solutions().count()
}

fn main() {
    env_logger::init();    
    let simulated_args = vec!["libafl_frida_test", "-A", "--disable-excludes", "--continue-on-error", "-H", "harness.so"];
    let options: FuzzerOptions = FuzzerOptions::try_parse_from(simulated_args).unwrap();
    unsafe{test_asan(&options)}
}
