mod input;

#[cfg(windows)]
use std::ptr::write_volatile;
use std::{path::PathBuf, ptr::write};

use input::{
    CustomInput, CustomInputGenerator, ToggleBooleanMutator, ToggleOptionalByteArrayMutator,
};
#[cfg(feature = "simple_interface")]
use libafl::mutators::{
    havoc_mutations::{mapped_havoc_mutations, optional_mapped_havoc_mutations},
    numeric::mapped_int_mutators,
};
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::SimpleMonitor,
    mutators::scheduled::StdScheduledMutator,
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{
    current_nanos, nonzero,
    rands::StdRand,
    tuples::{tuple_list, Merge, Prepend},
};
#[cfg(not(feature = "simple_interface"))]
use {
    libafl::mutators::{
        havoc_mutations::{havoc_crossover_with_corpus_mapper, havoc_mutations_no_crossover},
        mapping::{ToMappingMutator, ToOptionalMutator},
        numeric::{int_mutators_no_crossover, mapped_int_mutators_crossover},
    },
    libafl_bolts::tuples::Map,
};

/// Coverage map with explicit assignments due to the lack of instrumentation
const SIGNALS_LEN: usize = 16;
static mut SIGNALS: [u8; SIGNALS_LEN] = [0; 16];
static mut SIGNALS_PTR: *mut u8 = &raw mut SIGNALS as _;

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    if idx > 3 {
        println!("Setting signal: {idx}");
    }
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}

#[expect(clippy::manual_assert)]
pub fn main() {
    // The closure that we want to fuzz
    // The pseudo program under test uses all parts of the custom input
    // We are manually setting bytes in a pseudo coverage map to guide the fuzzer
    let mut harness = |input: &CustomInput| {
        signals_set(0);
        if input.byte_array == vec![b'a'] {
            signals_set(1);
            if input.optional_byte_array == Some(vec![b'b']) {
                signals_set(2);
                // require input.num to be in the top 1% of possible values
                if input.num > i16::MAX - i16::MAX / 50 {
                    signals_set(3);
                    if input.boolean {
                        #[cfg(unix)]
                        panic!("Artificial bug triggered =)");

                        // panic!() raises a STATUS_STACK_BUFFER_OVERRUN exception which cannot be caught by the exception handler.
                        // Here we make it raise STATUS_ACCESS_VIOLATION instead.
                        // Extending the windows exception handler is a TODO. Maybe we can refer to what winafl code does.
                        // https://github.com/googleprojectzero/winafl/blob/ea5f6b85572980bb2cf636910f622f36906940aa/winafl.c#L728
                        #[cfg(windows)]
                        unsafe {
                            write_volatile(0 as *mut u32, 0);
                        }
                    }
                }
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map

    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS_LEN) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
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

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

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

    // Generator of printable bytearrays of max size 32
    let mut generator = CustomInputGenerator::new(nonzero!(1));

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    #[cfg(feature = "simple_interface")]
    let (mapped_mutators, optional_mapped_mutators, int_mutators) = {
        // Creating mutators that will operate on input.byte_array
        let mapped_mutators =
            mapped_havoc_mutations(CustomInput::byte_array_mut, CustomInput::byte_array);

        // Creating mutators that will operate on input.optional_byte_array
        let optional_mapped_mutators = optional_mapped_havoc_mutations(
            CustomInput::optional_byte_array_mut,
            CustomInput::optional_byte_array,
        );

        let int_mutators = mapped_int_mutators(CustomInput::num_mut, CustomInput::num);
        (mapped_mutators, optional_mapped_mutators, int_mutators)
    };

    #[cfg(not(feature = "simple_interface"))]
    let (mapped_mutators, optional_mapped_mutators, int_mutators) = {
        // Creating mutators that will operate on input.byte_array
        let mapped_mutators = havoc_mutations_no_crossover()
            .merge(havoc_crossover_with_corpus_mapper(CustomInput::byte_array))
            .map(ToMappingMutator::new(CustomInput::byte_array_mut));

        // Creating mutators that will operate on input.optional_byte_array
        let optional_mapped_mutators = havoc_mutations_no_crossover()
            .merge(havoc_crossover_with_corpus_mapper(
                CustomInput::optional_byte_array,
            ))
            .map(ToOptionalMutator)
            .map(ToMappingMutator::new(CustomInput::optional_byte_array_mut));

        // Creating mutators that will operate on input.num
        let int_mutators = int_mutators_no_crossover()
            .merge(mapped_int_mutators_crossover(CustomInput::num))
            .map(ToMappingMutator::new(CustomInput::num_mut));
        (mapped_mutators, optional_mapped_mutators, int_mutators)
    };

    // Merging multiple lists of mutators that mutate a sub-part of the custom input
    // This collection could be expanded with default or custom mutators as needed for the input
    let mutators = tuple_list!()
        // First, mutators for the simple byte array
        .merge(mapped_mutators)
        // Then, mutators for the optional byte array, these return MutationResult::Skipped if the part is not present
        .merge(optional_mapped_mutators)
        // Then, mutators for the number
        .merge(int_mutators)
        // A custom mutator that sets the optional byte array to None if present, and generates a random byte array of length 1 if it is not
        .prepend(ToggleOptionalByteArrayMutator::new(nonzero!(1)))
        // Finally, a custom mutator that toggles the boolean part of the input
        .prepend(ToggleBooleanMutator);

    // Scheduling layer for the mutations
    let mutator_scheduler = StdScheduledMutator::new(mutators);
    // Defining the mutator stage
    let mut stages = tuple_list!(StdMutationalStage::new(mutator_scheduler));

    // Run the fuzzer
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
