use std::{
    ffi::c_int,
    fs::{read, write},
};

use libafl::{
    corpus::{Corpus, HasTestcase, InMemoryCorpus, Testcase},
    events::SimpleEventManager,
    executors::{inprocess_fork::InProcessForkExecutor, ExitKind},
    feedbacks::{CrashFeedback, TimeoutFeedback},
    inputs::{BytesInput, HasFixedMutatorBytes, HasTargetBytes},
    mutators::{havoc_mutations_no_crossover, Mutator, StdScheduledMutator},
    schedulers::QueueScheduler,
    stages::StdTMinMutationalStage,
    state::{HasCorpus, StdState},
    Error, ExecutesInput, Fuzzer, StdFuzzer,
};
use libafl_bolts::{
    rands::{RomuDuoJrRand, StdRand},
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
    AsSlice, HasLen,
};
use libafl_targets::LLVMCustomMutator;

use crate::{options::LibfuzzerOptions, CustomMutationStatus};

type TMinState =
    StdState<InMemoryCorpus<BytesInput>, BytesInput, RomuDuoJrRand, InMemoryCorpus<BytesInput>>;

fn minimize_crash_with_mutator<M: Mutator<BytesInput, TMinState>>(
    options: &LibfuzzerOptions,
    harness: extern "C" fn(*const u8, usize) -> c_int,
    mutator: M,
    mut state: TMinState,
) -> Result<(), Error> {
    let mut mgr = SimpleEventManager::printing();

    assert_eq!(
        options.dirs().len(),
        1,
        "Must provide exactly one input to minimise"
    );
    assert!(options.dirs()[0].exists(), "Input specified does not exist");
    assert!(options.dirs()[0].is_file(), "Input specified is not a file");

    let input = BytesInput::new(read(&options.dirs()[0])?);

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();

        let result = unsafe {
            crate::libafl_libfuzzer_test_one_input(Some(harness), buf.as_ptr(), buf.len())
        };
        match result {
            -2 => ExitKind::Crash,
            _ => ExitKind::Ok,
        }
    };

    let mut fuzzer = StdFuzzer::new(QueueScheduler::new(), (), ());

    let shmem_provider = StdShMemProvider::new()?;
    let mut executor = InProcessForkExecutor::new(
        &mut harness,
        (),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        options.timeout(),
        shmem_provider,
    )?;

    let exit_kind = fuzzer.execute_input(&mut state, &mut executor, &mut mgr, &input)?;

    let size = input.len();
    let id = state.corpus_mut().add(Testcase::new(input))?;

    match exit_kind {
        ExitKind::Crash => {
            let factory = CrashFeedback::new();
            let tmin = StdTMinMutationalStage::new(
                mutator,
                factory,
                if options.runs() == 0 {
                    128
                } else {
                    options.runs()
                },
            );
            let mut stages = tuple_list!(tmin);
            fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
        }
        ExitKind::Timeout => {
            let factory = TimeoutFeedback::new();
            let tmin = StdTMinMutationalStage::new(
                mutator,
                factory,
                if options.runs() == 0 {
                    128
                } else {
                    options.runs()
                },
            );
            let mut stages = tuple_list!(tmin);
            fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;
        }
        kind => unimplemented!("Unsupported exit kind for test minification: {:?}", kind),
    }

    let mut testcase = state.testcase_mut(id)?;
    let input = testcase.load_input(state.corpus())?.bytes().to_vec();
    drop(testcase);
    if input.len() >= size {
        eprintln!(
            "Unable to reduce {}",
            options.dirs()[0].as_path().as_os_str().to_str().unwrap()
        );
    } else {
        let mut dest = options.artifact_prefix().dir().clone();
        dest.push(format!(
            "{}minimized-from-{}",
            options.artifact_prefix().filename_prefix(),
            options.dirs()[0].file_name().unwrap().to_str().unwrap()
        ));
        write(&dest, input)?;
        println!(
            "Wrote minimised input to {}",
            dest.file_name().unwrap().to_str().unwrap()
        );
    }

    Ok(())
}

pub fn minimize_crash(
    options: &LibfuzzerOptions,
    harness: extern "C" fn(*const u8, usize) -> c_int,
) -> Result<(), Error> {
    println!(
        "Attempting to minimise a crash: {}",
        options
            .dirs()
            .iter()
            .map(|p| p
                .to_str()
                .expect("Couldn't render the filename as a string!"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mutator_status = CustomMutationStatus::new();

    let state = StdState::new(
        StdRand::new(),
        InMemoryCorpus::<BytesInput>::new(),
        InMemoryCorpus::new(),
        &mut (),
        &mut (),
    )?;

    // TODO configure with mutation stacking options from libfuzzer
    if mutator_status.custom_mutation {
        let custom_mutator = unsafe {
            LLVMCustomMutator::mutate_unchecked(StdScheduledMutator::new(
                havoc_mutations_no_crossover(),
            ))
        };
        minimize_crash_with_mutator(options, harness, custom_mutator, state)
    } else {
        let std_mutator = StdScheduledMutator::new(havoc_mutations_no_crossover());
        minimize_crash_with_mutator(options, harness, std_mutator, state)
    }
}
